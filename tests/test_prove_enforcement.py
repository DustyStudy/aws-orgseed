"""
Tests for cli/prove_enforcement.py - the script that shows a guardrail SCP actually
enforces in a member account, by comparing the SAME calls with and without it.

The classification matters more than it looks: a call denied for the wrong reason
(a missing permission, a typo) would look exactly like the SCP working. So only an
AccessDenied that names a *service control policy* counts as enforcement.
"""
import pytest
from botocore.exceptions import ClientError

import prove_enforcement as pe


def err(code, message="x"):
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


SCP_DENY = "User: arn:aws:sts::1:assumed-role/r/s is not authorized to perform: ec2:RunInstances on resource: arn:aws:ec2:*:*:instance/* with an explicit deny in a service control policy"


@pytest.mark.parametrize("code", ["DryRunOperation", "TrailNotFoundException", "NoSuchConfigurationRecorderException"])
def test_a_call_that_reached_the_service_is_authorized(code):
    assert pe.classify(err(code)) == pe.AUTHORIZED


def test_a_call_that_succeeds_is_authorized():
    assert pe.classify(None) == pe.AUTHORIZED


@pytest.mark.parametrize("code", ["UnauthorizedOperation", "AccessDenied", "AccessDeniedException"])
def test_only_a_denial_that_names_an_scp_counts_as_enforcement(code):
    assert pe.classify(err(code, SCP_DENY)) == pe.DENIED_BY_SCP


@pytest.mark.parametrize("code", ["UnauthorizedOperation", "AccessDenied"])
def test_a_denial_for_any_other_reason_is_not_credited_to_the_scp(code):
    assert pe.classify(err(code, "User is not authorized to perform: ec2:RunInstances because no identity-based policy allows it")) == pe.DENIED_OTHER


def test_an_unrelated_error_is_an_error_not_a_verdict():
    assert pe.classify(err("Throttling", "slow down")) == pe.ERROR


def results(**overrides):
    base = {
        "imdsv1_launch": pe.DENIED_BY_SCP,
        "imdsv2_launch": pe.AUTHORIZED,
        "implicit_launch_imdsv2_ami": pe.AUTHORIZED,
        "implicit_launch_legacy_ami": pe.DENIED_BY_SCP,
        "stop_cloudtrail": pe.DENIED_BY_SCP,
        "stop_config": pe.DENIED_BY_SCP,
    }
    base.update(overrides)
    return base


def test_with_scp_the_guardrails_must_be_denied_by_the_scp_and_the_control_allowed():
    assert pe.evaluate("with-scp", results()) == []


def test_with_scp_a_call_that_is_still_allowed_is_a_failure():
    failures = pe.evaluate("with-scp", results(stop_cloudtrail=pe.AUTHORIZED))
    assert len(failures) == 1 and "stop_cloudtrail" in failures[0]


def test_with_scp_a_denial_for_the_wrong_reason_is_a_failure():
    failures = pe.evaluate("with-scp", results(imdsv1_launch=pe.DENIED_OTHER))
    assert len(failures) == 1 and "imdsv1_launch" in failures[0]


def test_the_control_being_denied_invalidates_the_experiment():
    """If the call that SHOULD work is blocked, the account is broken in some other
    way and none of the other results mean anything."""
    failures = pe.evaluate("with-scp", results(imdsv2_launch=pe.DENIED_BY_SCP))
    assert any("imdsv2_launch" in f for f in failures)


@pytest.mark.parametrize("phase", ["no-scp"])
def test_without_the_scp_everything_must_be_authorized(phase):
    assert pe.evaluate(phase, {k: pe.AUTHORIZED for k in results()}) == []
    failures = pe.evaluate(phase, results())
    assert {f.split(":")[0] for f in failures} == {"imdsv1_launch", "implicit_launch_legacy_ami", "stop_cloudtrail", "stop_config"}


def test_observation_only_probes_are_reported_but_never_fail_a_phase(monkeypatch):
    monkeypatch.setitem(pe.PROBES, "extra", None)
    r = results()
    r["extra"] = pe.DENIED_BY_SCP
    assert pe.evaluate("with-scp", r) == []
    r["extra"] = pe.AUTHORIZED
    assert pe.evaluate("with-scp", r) == []


def test_a_launch_that_sets_nothing_is_judged_by_what_the_image_defaults_to():
    """The SCP resolves ec2:MetadataHttpTokens from the image when the request leaves
    it unset: an IMDSv2-by-default image (AL2023) is allowed - the instance IS IMDSv2 -
    while an image that defaults to IMDSv1 is denied. Both are asserted, so the
    guardrail is shown to catch the implicit case, not only the explicit one."""
    assert pe.PROBES["implicit_launch_imdsv2_ami"] is False
    assert pe.PROBES["implicit_launch_legacy_ami"] is True
    assert pe.evaluate("with-scp", results(implicit_launch_legacy_ami=pe.AUTHORIZED)) != []


def test_a_probe_that_could_not_run_is_skipped_not_failed():
    """E.g. the legacy public AMI parameter is retired: nothing to assert about it."""
    r = results()
    del r["implicit_launch_legacy_ami"]
    assert pe.evaluate("with-scp", r) == []


def test_an_unknown_phase_is_refused():
    with pytest.raises(ValueError, match="phase"):
        pe.evaluate("sometimes", results())
