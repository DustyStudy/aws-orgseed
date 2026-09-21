"""
Prove that the guardrail SCP actually enforces, in a real member account.

    prove_enforcement.py --account <test-account-id> --role <role> --phase no-scp
    (apply the SCP)
    prove_enforcement.py --account <test-account-id> --role <role> --phase with-scp --wait 120
    (destroy it)
    prove_enforcement.py --account <test-account-id> --role <role> --phase no-scp --wait 120

Run with credentials for the MANAGEMENT account (profile / environment); the script
assumes --role in the test account and makes a handful of calls that the baseline SCP
denies. The same calls are made in every phase, so the only variable is the SCP:
denied while it is attached, allowed before and after. That before/after toggle is
what shows the SCP - and not a missing permission or a typo - was the cause.

It creates nothing: EC2 launches are dry runs, and the CloudTrail / Config calls
target a trail and a recorder that do not exist (so an *authorized* call fails with a
"not found" error, and a *denied* one fails with AccessDenied).

Exits non-zero if reality does not match the phase's expectation.
"""
import argparse
import datetime
import json
import sys
import time

import boto3
from botocore.exceptions import ClientError

AUTHORIZED = "authorized"
DENIED_BY_SCP = "denied_by_scp"
DENIED_OTHER = "denied_other"
ERROR = "error"

# Errors that mean "the call reached the service and was allowed to run".
AUTHORIZED_CODES = {"DryRunOperation", "TrailNotFoundException", "NoSuchConfigurationRecorderException"}
DENY_CODES = {"UnauthorizedOperation", "AccessDenied", "AccessDeniedException"}

# name -> True: the baseline SCP must block it. False: a control that must always
# work (if it doesn't, the account is broken some other way and nothing else means
# anything). None: reported for information only, never a pass/fail.
PROBES = {
    "imdsv1_launch": True,
    "imdsv2_launch": False,
    # A launch that sets no metadata options at all is judged by what the IMAGE
    # defaults to: an IMDSv2-by-default image (AL2023) yields an IMDSv2 instance and is
    # allowed; an image that defaults to IMDSv1 is denied. Both are asserted, so the
    # guardrail is shown to catch the implicit case and not only the explicit one.
    "implicit_launch_imdsv2_ami": False,
    "implicit_launch_legacy_ami": True,
    "stop_cloudtrail": True,
    "stop_config": True,
}
PHASES = ("no-scp", "with-scp")


def classify(exc):
    """Only an AccessDenied that NAMES a service control policy counts as enforcement.
    A call denied for any other reason must not be credited to the SCP."""
    if exc is None:
        return AUTHORIZED
    if not isinstance(exc, ClientError):
        return ERROR
    code = exc.response.get("Error", {}).get("Code", "")
    message = exc.response.get("Error", {}).get("Message", "")
    if code in AUTHORIZED_CODES:
        return AUTHORIZED
    if code in DENY_CODES:
        return DENIED_BY_SCP if "service control policy" in message.lower() else DENIED_OTHER
    return ERROR


def evaluate(phase, results):
    """Return a list of failures ('name: expected X, got Y'); empty means the phase holds."""
    if phase not in PHASES:
        raise ValueError(f"phase must be one of {PHASES}, got {phase!r}")
    failures = []
    for name, blocked in PROBES.items():
        if name not in results or blocked is None:
            continue
        expected = DENIED_BY_SCP if (phase == "with-scp" and blocked) else AUTHORIZED
        if results[name] != expected:
            failures.append(f"{name}: expected {expected}, got {results[name]}")
    return failures


def _try(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - every outcome is data here
        return classify(exc)
    return classify(None)


MODERN_AMI = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
LEGACY_AMI = "/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"


def _legacy_ami(ssm, ec2):
    """An image that does NOT default to IMDSv2, or None if there isn't one to use
    (the public parameter can be retired; then that probe is skipped, not failed)."""
    try:
        ami = ssm.get_parameter(Name=LEGACY_AMI)["Parameter"]["Value"]
        if ec2.describe_images(ImageIds=[ami])["Images"][0].get("ImdsSupport") == "v2.0":
            return None
        return ami
    except (ClientError, IndexError):
        return None


def run_probes(session, region="us-east-1"):
    ec2 = session.client("ec2", region_name=region)
    ssm = session.client("ssm", region_name=region)
    modern = ssm.get_parameter(Name=MODERN_AMI)["Parameter"]["Value"]
    legacy = _legacy_ami(ssm, ec2)

    def launch(ami, **extra):
        return lambda: ec2.run_instances(ImageId=ami, InstanceType="t3.micro", MinCount=1, MaxCount=1, DryRun=True, **extra)

    results = {
        "imdsv1_launch": _try(launch(modern, MetadataOptions={"HttpTokens": "optional"})),
        "imdsv2_launch": _try(launch(modern, MetadataOptions={"HttpTokens": "required"})),
        "implicit_launch_imdsv2_ami": _try(launch(modern)),
        "stop_cloudtrail": _try(lambda: session.client("cloudtrail", region_name=region).stop_logging(Name="orgseed-proof-nonexistent")),
        "stop_config": _try(lambda: session.client("config", region_name=region).stop_configuration_recorder(ConfigurationRecorderName="orgseed-proof-nonexistent")),
    }
    if legacy:
        results["implicit_launch_legacy_ami"] = _try(launch(legacy))
    return results


def assume(session, account, role):
    c = session.client("sts").assume_role(RoleArn=f"arn:aws:iam::{account}:role/{role}", RoleSessionName="orgseed-proof")["Credentials"]
    return boto3.Session(aws_access_key_id=c["AccessKeyId"], aws_secret_access_key=c["SecretAccessKey"], aws_session_token=c["SessionToken"])


def main(argv=None, session=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--account", required=True, help="test member account ID")
    p.add_argument("--role", default="OrganizationAccountAccessRole", help="role to assume in the test account")
    p.add_argument("--phase", required=True, choices=PHASES)
    p.add_argument("--region", default="us-east-1")
    p.add_argument("--profile", help="AWS profile for the management account (default: environment)")
    p.add_argument("--wait", type=int, default=0, metavar="SECONDS", help="keep re-checking up to this long: SCP changes take a moment to propagate")
    p.add_argument("--out", help="write the evidence as JSON to this file")
    args = p.parse_args(argv)

    mgmt = session or boto3.Session(profile_name=args.profile)
    deadline = time.time() + args.wait
    while True:
        test = assume(mgmt, args.account, args.role)  # fresh session each pass
        results = run_probes(test, args.region)
        failures = evaluate(args.phase, results)
        if not failures or time.time() >= deadline:
            break
        time.sleep(10)

    masked = "*" * 8 + args.account[-4:]
    print(f"phase: {args.phase}   account: {masked}   role: {args.role}   {datetime.datetime.now(datetime.timezone.utc):%Y-%m-%d %H:%M:%SZ}")
    for name, verdict in results.items():
        role = {True: "guardrail", False: "control", None: "observe"}[PROBES[name]]
        print(f"  {name:18} {role:10} {verdict}")
    print("RESULT:", "PASS - matches the expectation for this phase" if not failures else "FAIL - " + "; ".join(failures))

    if args.out:
        with open(args.out, "w") as f:
            json.dump({"phase": args.phase, "account": masked, "role": args.role, "time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "results": results, "failures": failures}, f, indent=2)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
