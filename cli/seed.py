"""
aws-orgseed CLI orchestrator.

Two modes:

  --init ALIAS
      One-time, one-org bootstrap. Run this using initial admin/break-glass
      credentials for that org (via AWS_PROFILE, env vars, or an assumed
      role you set up manually) -- NOT the hub role. Deploys
      bootstrap/org-seeding-role.yaml and bootstrap/state-backend.yaml
      directly into that org's management account.

  (no --init)
      Ongoing mode. Assumes the current credentials ARE the hub role
      (true in CI, where configure-aws-credentials assumes it via OIDC).
      For every org in the config, assumes into that org's
      TerraformCiRoleArn is NOT touched here -- this path only re-applies
      the bootstrap stacks (idempotent update) and regenerates backend.tf
      files. Ongoing application changes belong in modules/, run as normal
      Terraform through the CI role, not through this script.

Either mode writes cli/output/<alias>/backend.tf so Terraform in modules/
can be pointed at the right state location.
"""
import argparse
import pathlib
import sys

import boto3
import yaml

HERE = pathlib.Path(__file__).parent
BOOTSTRAP_DIR = HERE.parent / "bootstrap"
OUTPUT_DIR = HERE / "output"


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def partition_arn(account_id: str, partition: str, role_name: str) -> str:
    return f"arn:{partition}:iam::{account_id}:role/{role_name}"


def deploy_stack(cfn_client, stack_name: str, template_path: pathlib.Path, params: dict):
    """Create or update a CFN stack, waiting for completion. Idempotent."""
    with open(template_path, "r") as f:
        template_body = f.read()

    parameters = [{"ParameterKey": k, "ParameterValue": str(v)} for k, v in params.items()]

    try:
        cfn_client.describe_stacks(StackName=stack_name)
        exists = True
    except cfn_client.exceptions.ClientError:
        exists = False

    common = {
        "StackName": stack_name,
        "TemplateBody": template_body,
        "Parameters": parameters,
        "Capabilities": ["CAPABILITY_NAMED_IAM"],
        "Tags": [{"Key": "orgseed:managed", "Value": "true"}],
    }

    if exists:
        try:
            cfn_client.update_stack(**common)
            waiter = cfn_client.get_waiter("stack_update_complete")
        except cfn_client.exceptions.ClientError as e:
            if "No updates are to be performed" in str(e):
                print(f"  {stack_name}: no changes")
                return
            raise
    else:
        cfn_client.create_stack(**common)
        waiter = cfn_client.get_waiter("stack_create_complete")

    print(f"  {stack_name}: waiting for {'update' if exists else 'create'} to complete...")
    waiter.wait(StackName=stack_name)
    print(f"  {stack_name}: done")


def assume_role(sts_client, role_arn: str, session_name: str):
    resp = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def write_backend_tf(alias: str, org: dict):
    out_dir = OUTPUT_DIR / alias
    out_dir.mkdir(parents=True, exist_ok=True)
    region = org["regions"][0]
    lines = [
        'terraform {',
        '  backend "s3" {',
        f'    bucket = "{org["state_bucket"]}"',
        f'    key    = "orgseed/{alias}/terraform.tfstate"',
        f'    region = "{region}"',
    ]
    if org.get("use_lock_table") and org.get("lock_table"):
        lines.append(f'    dynamodb_table = "{org["lock_table"]}"')
    else:
        lines.append('    use_lockfile = true')
    lines += ['  }', '}', '']
    (out_dir / "backend.tf").write_text("\n".join(lines))
    print(f"  wrote {out_dir / 'backend.tf'}")


def bootstrap_org(session: boto3.Session, alias: str, org: dict):
    print(f"Bootstrapping {alias} ({org['management_account_id']}, {org['partition']})")
    region = org["regions"][0]
    cfn = session.client("cloudformation", region_name=region)

    deploy_stack(
        cfn,
        stack_name=f"orgseed-roles-{alias}",
        template_path=BOOTSTRAP_DIR / "org-seeding-role.yaml",
        params={
            "HubRoleArn": org["_hub_role_arn"],
            "OrgAlias": alias,
            "SeedingAdminRoleName": org["seeding_admin_role_name"],
            "TerraformCiRoleName": org["ci_role_name"],
        },
    )
    deploy_stack(
        cfn,
        stack_name=f"orgseed-state-{alias}",
        template_path=BOOTSTRAP_DIR / "state-backend.yaml",
        params={
            "OrgAlias": alias,
            "StateBucketName": org["state_bucket"],
            "UseLockTable": str(org.get("use_lock_table", False)).lower(),
            "LockTableName": org.get("lock_table", ""),
        },
    )
    write_backend_tf(alias, org)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", default=str(HERE / "orgs.yaml"))
    parser.add_argument("--init", metavar="ALIAS", help="One-time bootstrap for a single org using current (non-hub) credentials")
    parser.add_argument("--org", metavar="ALIAS", help="Limit ongoing-mode run to a single org")
    args = parser.parse_args()

    config = load_config(args.config)
    orgs = {o["alias"]: o for o in config["orgs"]}

    if args.init:
        if args.init not in orgs:
            sys.exit(f"Unknown org alias: {args.init}")
        org = orgs[args.init]
        org["_hub_role_arn"] = config["hub_role_arn"]
        session = boto3.Session()  # current creds: initial admin/break-glass, NOT the hub role
        bootstrap_org(session, args.init, org)
        return

    # Ongoing mode: current creds ARE the hub role (assumed via OIDC in CI).
    hub_session = boto3.Session()
    sts = hub_session.client("sts")

    targets = [args.org] if args.org else list(orgs.keys())
    for alias in targets:
        org = orgs[alias]
        org["_hub_role_arn"] = config["hub_role_arn"]
        seeding_admin_arn = partition_arn(
            org["management_account_id"], org["partition"], org["seeding_admin_role_name"]
        )
        org_session = assume_role(sts, seeding_admin_arn, session_name=f"orgseed-{alias}")
        bootstrap_org(org_session, alias, org)


if __name__ == "__main__":
    main()
