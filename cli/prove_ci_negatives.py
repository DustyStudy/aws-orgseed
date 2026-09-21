"""
Prove, with REAL calls, that the orgseed-ci role cannot escalate or stray.

Run it as that role - in CI, through the actual GitHub OIDC -> orgseed-hub -> orgseed-ci
chain (.github/workflows/prove.yml) - not from an admin session, or it proves nothing.

    prove_ci_negatives.py --backend-hcl stacks/baseline/backend.hcl [--out evidence.json]

It makes three kinds of call and checks each got the RIGHT kind of answer:

  self_escalation   editing the CI role's own permissions, rewriting the bootstrap admin
                    role's trust, touching the bootstrap stacks. Must hit an EXPLICIT deny
                    in an identity-based policy: the belt-and-braces statement that keeps
                    these closed even if the role's allow statements are ever broadened.
  outside_scope     things the role was never granted (read EC2, list IAM users, change
                    the state bucket's policy, move accounts between OUs). Must fail because
                    NO policy allows them - least privilege by omission. (Some services tell
                    the caller only "no permission"; CloudTrail records IAM's own reason.)
  control           what the role IS for (read the org, read its state bucket). Must work,
                    so a broken session can't masquerade as "everything denied".

SAFETY: this runs against a live management account. Every call that is expected to be
denied is harmless if it is wrongly ALLOWED - a nonexistent policy ARN, a deliberately
malformed document, a nonexistent stack - so a broken deny shows up as a failing check and
never as damage. tests/test_prove_ci_negatives.py enforces that property.

Nothing identifying is printed or written: not the account ID, not the state bucket.
Exits non-zero if any call got an unexpected answer.
"""
import argparse
import datetime
import json
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass

import boto3
from botocore.exceptions import ClientError

AUTHORIZED = "authorized"
DENIED_EXPLICIT = "denied_explicit"  # explicit deny in an identity-based policy
DENIED_IMPLICIT = "denied_implicit"  # no identity-based policy allows it
DENIED_GENERIC = "denied_generic"    # denied, but the service told the CALLER too little to say which kind
DENIED_OTHER = "denied_other"        # denied, but not by this role's own policies (e.g. an SCP)
ERROR = "error"

MARKER = "orgseed-proof-nonexistent"

DENY_CODES = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation"}
# Not verdicts about authorization: a dead session or throttling says nothing.
NON_VERDICT_CODES = {
    "ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException",
    "SignatureDoesNotMatch", "Throttling", "ThrottlingException", "RequestLimitExceeded", "ServiceUnavailable",
}

# What each group must get. Self-escalation needs a CONFIRMED explicit deny. Outside-scope
# accepts an implicit deny OR a terse one: some services (Organizations, sometimes S3) tell
# the caller only "you don't have permissions" while IAM's own record in CloudTrail says
# "because no identity-based policy allows ...". A terse denial can't be told from an
# explicit one, so it never satisfies the self-escalation check.
EXPECT = {
    "self_escalation": {DENIED_EXPLICIT},
    "outside_scope": {DENIED_IMPLICIT, DENIED_GENERIC},
    "control": {AUTHORIZED},
}


def classify(exc):
    if exc is None:
        return AUTHORIZED
    if not isinstance(exc, ClientError):
        return ERROR
    code = exc.response.get("Error", {}).get("Code", "")
    message = exc.response.get("Error", {}).get("Message", "").lower()
    if code in NON_VERDICT_CODES:
        return ERROR
    if code in DENY_CODES:
        if "service control policy" in message:
            return DENIED_OTHER  # says nothing about this role's own policies
        if "explicit deny" in message and "identity-based policy" in message:
            return DENIED_EXPLICIT
        if "no identity-based policy allows" in message:
            return DENIED_IMPLICIT
        return DENIED_GENERIC
    return AUTHORIZED  # an error AFTER authorization (NoSuchEntity, MalformedPolicyDocument, ...) means it was allowed


@dataclass
class Probe:
    name: str
    group: str
    mutating: bool
    call: Callable  # (session, ctx) -> None; raises whatever AWS raises


def build_probes():
    def fake_policy_arn(c):
        return f"arn:aws:iam::{c['account']}:policy/{MARKER}"

    return [
        # --- self_escalation: each is inert if wrongly allowed ------------------------------
        Probe("delete_own_inline_policy", "self_escalation", True,
              lambda s, c: s.client("iam").delete_role_policy(RoleName=c["ci_role"], PolicyName=MARKER)),
        Probe("detach_own_policy", "self_escalation", True,
              lambda s, c: s.client("iam").detach_role_policy(RoleName=c["ci_role"], PolicyArn=fake_policy_arn(c))),
        Probe("attach_policy_to_admin_role", "self_escalation", True,
              lambda s, c: s.client("iam").attach_role_policy(RoleName=c["admin_role"], PolicyArn=fake_policy_arn(c))),
        # A malformed document: IAM rejects it before applying it, so if the deny were
        # missing this fails with MalformedPolicyDocument and changes nothing.
        Probe("rewrite_admin_trust", "self_escalation", True,
              lambda s, c: s.client("iam").update_assume_role_policy(RoleName=c["admin_role"], PolicyDocument="{}")),
        Probe("put_own_inline_policy", "self_escalation", True,
              lambda s, c: s.client("iam").put_role_policy(RoleName=c["ci_role"], PolicyName=MARKER, PolicyDocument="{}")),
        Probe("update_bootstrap_stack", "self_escalation", True,
              lambda s, c: s.client("cloudformation").update_stack(StackName=f"orgseed-roles-{MARKER}", UsePreviousTemplate=True)),
        Probe("delete_bootstrap_stack", "self_escalation", True,
              lambda s, c: s.client("cloudformation").delete_stack(StackName=f"orgseed-roles-{MARKER}")),
        # --- outside_scope: never granted --------------------------------------------------
        Probe("describe_instances", "outside_scope", False, lambda s, c: s.client("ec2").describe_instances()),
        Probe("list_iam_users", "outside_scope", False, lambda s, c: s.client("iam").list_users()),
        Probe("list_all_buckets", "outside_scope", False, lambda s, c: s.client("s3").list_buckets()),
        # S3 answers NoSuchBucket for a nonexistent bucket BEFORE it checks permissions, so
        # a probe against one reads as 'authorized' whatever the role may do (the first real
        # run caught this). Use the EXISTING state bucket, with a malformed policy that S3
        # rejects if the call were ever wrongly allowed.
        Probe("change_state_bucket_policy", "outside_scope", True,
              lambda s, c: s.client("s3").put_bucket_policy(Bucket=c["state_bucket"], Policy="{}")),
        Probe("delete_ou", "outside_scope", True,
              lambda s, c: s.client("organizations").delete_organizational_unit(OrganizationalUnitId="ou-nonexistent-00000000")),
        Probe("move_account", "outside_scope", True,
              lambda s, c: s.client("organizations").move_account(AccountId="000000000000", SourceParentId="r-nonexistent", DestinationParentId="ou-nonexistent-00000000")),
        # The org root is a target IAM must refuse by default (AllowAttachToRoot=false).
        # PolicyId is a nonexistent SCP whose ARN matches the allowed policy pattern, so the
        # ROOT is the only thing that can cause a denial - and if the guard were missing
        # the call fails harmlessly with PolicyNotFound.
        Probe("attach_scp_to_root", "outside_scope", True,
              lambda s, c: s.client("organizations").attach_policy(PolicyId="p-nonexistent0", TargetId="r-nonexistent")),
        Probe("detach_scp_from_root", "outside_scope", True,
              lambda s, c: s.client("organizations").detach_policy(PolicyId="p-nonexistent0", TargetId="r-nonexistent")),
        # --- control: what the role is for -------------------------------------------------
        Probe("whoami", "control", False, lambda s, c: s.client("sts").get_caller_identity()),
        Probe("describe_organization", "control", False, lambda s, c: s.client("organizations").describe_organization()),
        Probe("list_scps", "control", False, lambda s, c: s.client("organizations").list_policies(Filter="SERVICE_CONTROL_POLICY")),
        Probe("read_state_bucket", "control", False,
              lambda s, c: s.client("s3").list_objects_v2(Bucket=c["state_bucket"], MaxKeys=1)),
    ]


def _try(call, session, ctx):
    try:
        call(session, ctx)
    except Exception as exc:  # noqa: BLE001 - every outcome is data here
        return classify(exc)
    return classify(None)


def run_probes(session, ctx):
    return {p.name: _try(p.call, session, ctx) for p in build_probes()}


def evaluate(results):
    """Failures as 'name: expected X, got Y'; empty means the role behaves as designed."""
    failures = []
    for p in build_probes():
        if p.name not in results:
            failures.append(f"{p.name}: no result")
            continue
        expected = EXPECT[p.group]
        if results[p.name] not in expected:
            failures.append(f"{p.name}: expected {'/'.join(sorted(expected))}, got {results[p.name]}")
    return failures


def read_bucket(path):
    with open(path) as f:
        m = re.search(r'^\s*bucket\s*=\s*"([^"]+)"', f.read(), re.MULTILINE)
    if not m:
        raise ValueError(f"no bucket found in {path}")
    return m.group(1)


def role_from_arn(arn):
    m = re.match(r"^arn:[^:]+:sts::\d+:assumed-role/([^/]+)/", arn)
    if not m:
        raise ValueError(f"expected an assumed role ARN, got a different principal type: {arn.split(':')[2:3]}")
    return m.group(1)


def main(argv=None, session=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--backend-hcl", required=True, help="rendered backend.hcl (read for the state bucket; never printed)")
    p.add_argument("--admin-role", default="OrgSeedAdmin", help="name of the bootstrap admin role to probe")
    p.add_argument("--out", help="write the evidence as JSON to this file")
    args = p.parse_args(argv)

    session = session or boto3.Session()
    who = session.client("sts").get_caller_identity()
    ctx = {"account": who["Account"], "ci_role": role_from_arn(who["Arn"]), "admin_role": args.admin_role, "state_bucket": read_bucket(args.backend_hcl)}

    results = run_probes(session, ctx)
    failures = evaluate(results)

    print(f"orgseed-ci least-privilege proof   {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M:%SZ}")
    for probe in build_probes():
        print(f"  {probe.group:16} {probe.name:28} {results[probe.name]}")
    print("RESULT:", "PASS - every call got the answer the design promises" if not failures else "FAIL - " + "; ".join(failures))

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "role": ctx["ci_role"],
                       "results": results, "failures": failures}, f, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
