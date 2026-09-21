"""
Render the Phase 1 stack's inputs from the org config.

    stack_inputs.py --config <orgs.yaml> --org <alias> --stack-dir stacks/baseline

Writes, into --stack-dir:
    backend.hcl            partial S3 backend config (bucket/key/region/locking)
    terraform.tfvars.json  the stack's variables

and prints `::add-mask::<value>` for every identifier BEFORE anything else, so a
public workflow log can't leak account IDs, the state bucket or the OU ID. When
GITHUB_OUTPUT is set it also emits `ci_role_arn` and `region` for the workflow's
role-chaining step.

The config is the same (secret, base64) file `seed.py` reads; per-org Phase 1
settings live under an optional `baseline:` key:

    orgs:
      - alias: sandbox
        ...
        baseline:
          scp_target_id: ou-xxxx-xxxxxxxx   # required; an OU, never the root
          enforce_imdsv2: true              # optional

Standard library + PyYAML only, like seed.py.
"""
import argparse
import json
import os
import pathlib
import re
import sys

import seed

OU_ID = re.compile(r"^ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}$")


def find_org(config: dict, alias: str) -> dict:
    for org in config["orgs"]:
        if org["alias"] == alias:
            return org
    sys.exit(f"Unknown org alias: {alias}")


def render_backend_hcl(alias: str, org: dict) -> str:
    lines = [
        f'bucket       = "{org["state_bucket"]}"',
        f'key          = "{seed.backend_key(alias)}"',
        f'region       = "{org["regions"][0]}"',
        "encrypt      = true",
    ]
    if org.get("use_lock_table") and org.get("lock_table"):
        lines.append(f'dynamodb_table = "{org["lock_table"]}"')
    else:
        lines.append("use_lockfile = true")
    return "\n".join(lines) + "\n"


def render_tfvars(alias: str, org: dict) -> dict:
    baseline = org["baseline"]
    tfvars = {
        "org_alias": alias,
        "partition": org["partition"],
        "ci_role_name": org["ci_role_name"],
        "scp_target_id": baseline["scp_target_id"],
    }
    if "enforce_imdsv2" in baseline:
        tfvars["enforce_imdsv2"] = bool(baseline["enforce_imdsv2"])
    return tfvars


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--org", required=True, metavar="ALIAS")
    parser.add_argument("--stack-dir", required=True)
    args = parser.parse_args(argv)

    config = seed.load_config(args.config)
    try:
        seed.validate_config(config)
    except (ValueError, TypeError) as e:
        sys.exit(f"Invalid {args.config}: {e}")
    org = find_org(config, args.org)

    baseline = org.get("baseline")
    if not isinstance(baseline, dict) or "scp_target_id" not in baseline:
        sys.exit(f"org '{args.org}' has no baseline.scp_target_id - Phase 1 needs the OU to attach the SCP to")
    if not OU_ID.match(str(baseline["scp_target_id"])):
        sys.exit(
            f"org '{args.org}': baseline.scp_target_id must be an OU ID (ou-xxxx-xxxxxxxx), "
            "never the organization root - an SCP on the root applies to every member account at once"
        )

    # Mask FIRST: everything below, and every later step, may print these.
    for value in (config.get("hub_account_id"), org["management_account_id"], org["state_bucket"], baseline["scp_target_id"]):
        if value:
            print(f"::add-mask::{value}")

    out = pathlib.Path(args.stack_dir)
    (out / "backend.hcl").write_text(render_backend_hcl(args.org, org))
    (out / "terraform.tfvars.json").write_text(json.dumps(render_tfvars(args.org, org), indent=2) + "\n")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        ci_role_arn = seed.partition_arn(org["management_account_id"], org["partition"], org["ci_role_name"])
        with open(github_output, "a") as f:
            f.write(f"ci_role_arn={ci_role_arn}\nregion={org['regions'][0]}\n")
    print(f"rendered backend.hcl and terraform.tfvars.json for '{args.org}' into {out}")


if __name__ == "__main__":
    main()
