"""
Tests for cli/prove_ci_negatives.py - real-call proof that the orgseed-ci role cannot
escalate or stray, run AS that role through the actual OIDC -> hub -> orgseed-ci chain.

Two properties matter more than any other here:

1. CLASSIFICATION. "Denied" is not one thing. The self-escalation calls are stopped by an
   EXPLICIT deny (belt-and-braces, so a future broadening of the allow statements can't
   reopen them); everything outside the role's remit is stopped by the ABSENCE of an
   allow. Only the right kind of denial counts for each group.

2. SAFETY. These calls run against a live management account. Every call that is
   EXPECTED to be denied must be harmless if it is wrongly ALLOWED - a nonexistent policy
   ARN, a deliberately malformed document, a nonexistent stack - so a broken deny shows
   up as a failing check, never as damage. That is enforced below.
"""
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

import prove_ci_negatives as pn

CTX = {"account": "123456789012", "ci_role": "orgseed-ci", "admin_role": "OrgSeedAdmin", "state_bucket": "tfstate-x"}


def err(code, message="x"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


EXPLICIT = "User: arn:aws:sts::1:assumed-role/orgseed-ci/s is not authorized to perform: iam:PutRolePolicy on resource: role orgseed-ci with an explicit deny in an identity-based policy"
IMPLICIT = "User: arn:aws:sts::1:assumed-role/orgseed-ci/s is not authorized to perform: ec2:DescribeInstances because no identity-based policy allows the ec2:DescribeInstances action"
SCP = "... with an explicit deny in a service control policy"


def test_an_explicit_identity_policy_deny_is_recognised():
    assert pn.classify(err("AccessDenied", EXPLICIT)) == pn.DENIED_EXPLICIT


def test_a_missing_allow_is_an_implicit_denial():
    assert pn.classify(err("UnauthorizedOperation", IMPLICIT)) == pn.DENIED_IMPLICIT


def test_an_scp_denial_is_neither_kind():
    """An SCP deny says nothing about this role's own policies."""
    assert pn.classify(err("AccessDenied", SCP)) == pn.DENIED_OTHER


@pytest.mark.parametrize("code", ["NoSuchEntity", "MalformedPolicyDocument", "ValidationError", "OrganizationalUnitNotFoundException"])
def test_an_error_after_authorization_means_the_call_was_allowed(code):
    assert pn.classify(err(code)) == pn.AUTHORIZED


def test_a_call_that_succeeds_was_allowed():
    assert pn.classify(None) == pn.AUTHORIZED


@pytest.mark.parametrize("code", ["ExpiredToken", "InvalidClientTokenId", "Throttling", "RequestLimitExceeded", "ServiceUnavailable"])
def test_credential_and_throttling_errors_are_not_verdicts(code):
    """An expired session must not be mistaken for 'allowed'."""
    assert pn.classify(err(code)) == pn.ERROR


def test_a_non_aws_error_is_an_error():
    assert pn.classify(ValueError("boom")) == pn.ERROR


def all_expected():
    return {p.name: pn.EXPECT[p.group] for p in pn.build_probes()}


def test_everything_behaving_as_designed_passes():
    assert pn.evaluate(all_expected()) == []


def test_a_self_escalation_call_that_is_allowed_is_a_failure():
    r = all_expected()
    r["rewrite_admin_trust"] = pn.AUTHORIZED
    failures = pn.evaluate(r)
    assert len(failures) == 1 and failures[0].startswith("rewrite_admin_trust")


def test_a_self_escalation_call_needs_the_EXPLICIT_deny_not_just_a_missing_allow():
    """Denied only implicitly = the belt-and-braces deny is missing or unused: one
    future broadening of the allow statements away from being open."""
    r = all_expected()
    r["put_own_inline_policy"] = pn.DENIED_IMPLICIT
    assert any(f.startswith("put_own_inline_policy") for f in pn.evaluate(r))


def test_a_control_being_denied_invalidates_the_run():
    r = all_expected()
    r["whoami"] = pn.DENIED_IMPLICIT
    assert any(f.startswith("whoami") for f in pn.evaluate(r))


def test_every_group_is_covered():
    groups = {p.group for p in pn.build_probes()}
    assert groups == {"self_escalation", "outside_scope", "control"}


# --- SAFETY -------------------------------------------------------------------------------

# Calls that would do real damage if ever allowed. No probe may make any of them.
NEVER = {
    "leave_organization", "create_user", "create_access_key", "create_role", "delete_role",
    "create_policy", "delete_policy", "delete_bucket", "delete_object", "put_object",
    "terminate_instances", "run_instances", "remove_account_from_organization", "close_account",
    "create_organizational_unit", "attach_policy", "detach_policy", "delete_account",
}


class Recorder:
    """A stand-in session: every client method just records its call and 'succeeds'."""

    def __init__(self):
        self.calls = []

    def client(self, service, **_):
        rec = self

        class Client:
            def __getattr__(self_inner, method):
                def call(**kwargs):
                    rec.calls.append((service, method, kwargs))
                    return {}
                return call

        return Client()


def run_all_recorded():
    rec = Recorder()
    for probe in pn.build_probes():
        probe.call(rec, CTX)
    return rec.calls


def test_no_probe_makes_a_destructive_call():
    for service, method, _ in run_all_recorded():
        assert method not in NEVER, f"{service}.{method} must never be called by a probe"


def test_the_guarded_mutating_calls_are_inert_even_if_wrongly_allowed():
    """Each 'must be denied' call targets a nonexistent thing or carries a document that
    IAM rejects as malformed - so if the deny were missing the call would fail harmlessly."""
    calls = {(s, m): kw for s, m, kw in run_all_recorded()}
    marker = pn.MARKER
    assert marker in calls[("iam", "delete_role_policy")]["PolicyName"]
    assert marker in calls[("iam", "detach_role_policy")]["PolicyArn"]
    assert marker in calls[("iam", "attach_role_policy")]["PolicyArn"]
    assert calls[("iam", "update_assume_role_policy")]["PolicyDocument"] == "{}", "malformed on purpose: IAM rejects it before applying"
    put = calls[("iam", "put_role_policy")]
    assert put["PolicyDocument"] == "{}" and marker in put["PolicyName"]
    assert marker in calls[("cloudformation", "update_stack")]["StackName"]
    assert marker in calls[("cloudformation", "delete_stack")]["StackName"]
    assert "nonexistent" in calls[("organizations", "delete_organizational_unit")]["OrganizationalUnitId"]
    move = calls[("organizations", "move_account")]
    assert move["AccountId"] == "000000000000" and "nonexistent" in move["DestinationParentId"]


def test_the_mutating_probes_are_flagged_so_they_can_be_reviewed():
    mutating = {p.name for p in pn.build_probes() if p.mutating}
    assert {"delete_own_inline_policy", "rewrite_admin_trust", "update_bootstrap_stack", "move_account"} <= mutating
    assert not any(p.mutating for p in pn.build_probes() if p.group == "control")


def test_probe_names_are_unique():
    names = [p.name for p in pn.build_probes()]
    assert len(names) == len(set(names))


def test_the_backend_bucket_is_read_from_hcl_without_being_printed(tmp_path):
    hcl = tmp_path / "backend.hcl"
    hcl.write_text('bucket       = "tfstate-secret-bucket"\nkey          = "orgseed/x/terraform.tfstate"\n')
    assert pn.read_bucket(hcl) == "tfstate-secret-bucket"


def test_the_ci_role_name_comes_from_the_live_caller_identity():
    assert pn.role_from_arn("arn:aws:sts::123456789012:assumed-role/orgseed-ci/orgseed-terraform") == "orgseed-ci"
    with pytest.raises(ValueError, match="assumed role"):
        pn.role_from_arn("arn:aws:iam::123456789012:user/someone")


def test_main_reports_pass_and_writes_evidence_without_identifiers(tmp_path, monkeypatch, capsys):
    hcl = tmp_path / "backend.hcl"
    hcl.write_text('bucket = "tfstate-secret-bucket"\n')
    out = tmp_path / "evidence.json"
    by_name = {p.name: pn.EXPECT[p.group] for p in pn.build_probes()}
    monkeypatch.setattr(pn, "run_probes", lambda session, ctx: dict(by_name))
    session = MagicMock()
    session.client.return_value.get_caller_identity.return_value = {"Account": "123456789012", "Arn": "arn:aws:sts::123456789012:assumed-role/orgseed-ci/s"}
    rc = pn.main(["--backend-hcl", str(hcl), "--out", str(out)], session=session)
    printed = capsys.readouterr().out
    assert rc == 0 and "RESULT: PASS" in printed
    for secret in ("123456789012", "tfstate-secret-bucket"):
        assert secret not in printed and secret not in out.read_text()
