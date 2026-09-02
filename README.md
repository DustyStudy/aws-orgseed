# aws-orgseed

Multi-org AWS account seeding via Terraform, bootstrapped with OIDC — no long-lived
credentials, no per-org identity provider sprawl.

## The problem

Terraform can't manage an AWS Organization until an IAM role trusted by your CI's
OIDC provider already exists in that org's management account. But you can't create
that role *with* Terraform, because you have no credentials yet. `aws-orgseed` solves
this two-phase bootstrap problem across an arbitrary number of orgs from one config
file and one CI pipeline.

## Architecture: hub-and-spoke OIDC

Instead of creating a GitHub OIDC identity provider in every org (N providers to
maintain, N trust policies to audit), `aws-orgseed` uses one hub account:

```
GitHub Actions (OIDC token)
        |
        v
  Hub seeder role   <-- single OIDC provider lives here
        |
        | sts:AssumeRole (cross-account)
        v
  OrgSeedAdmin role in Org A     OrgSeedAdmin role in Org B  ...
        |                               |
        v                               v
  Bootstrap CFN stack             Bootstrap CFN stack
  (TerraformCI role,               (TerraformCI role,
   state bucket, lock table)        state bucket, lock table)
```

**Phase 0 — bootstrap (CloudFormation).** Run once per org, using whatever initial
admin access you have (break-glass, root, or credentials from `orgctl`). Deploys:
- `OrgSeedAdmin` role — trusts the hub role's ARN, used only during bootstrap
- `TerraformCI` role — trusts the hub role's ARN, used by every ongoing Terraform run
- S3 state bucket (+ DynamoDB lock table, or S3-native locking)

**Phase 1 — ongoing (Terraform).** Once bootstrapped, all further changes — SCP
guardrails, CloudTrail, IAM Identity Center baselines — run as normal Terraform,
authenticated via OIDC through the same hub-role chain. No static keys anywhere.

## Repo layout

```
bootstrap/                  CloudFormation — solves the chicken-and-egg problem
  oidc-provider.yaml          hub account only, created once
  org-seeding-role.yaml       deployed per target org (OrgSeedAdmin + TerraformCI)
  state-backend.yaml          per-org S3 state bucket + DynamoDB lock table
modules/                     Terraform, used after bootstrap
  org-baseline/                guardrail baseline (SCPs, CloudTrail, Config)
  ci-role/                     manage/rotate the TerraformCI trust policy
cli/
  seed.py                     orchestrates bootstrap across every org in orgs.yaml
  orgs.yaml                    declarative org list (accounts, regions, partitions)
  requirements.txt
examples/
  multi-org-example.yaml
.github/workflows/
  validate.yml                 cfn-lint, checkov, tflint, ruff, bandit
  seed.yml                      workflow_dispatch: runs cli/seed.py via OIDC
```

## Quickstart

1. Deploy `bootstrap/oidc-provider.yaml` once, in your hub account.
2. Edit `cli/orgs.yaml` with your org list (see `examples/multi-org-example.yaml`).
3. In each target org's management account, manually grant your hub role temporary
   admin access (or use existing break-glass access) — this is the one manual step
   that can't be automated away, by design.
4. Run `python cli/seed.py --config cli/orgs.yaml` to deploy the bootstrap stack into
   every org and generate a ready-to-use `backend.tf` for each.
5. From here on, Terraform runs in `.github/workflows/` authenticate via OIDC through
   the hub role automatically — no keys to rotate.

## GovCloud

Every org entry declares its own `partition` (`aws` or `aws-us-gov`). The CLI and
CFN templates branch on this rather than inferring it, matching the GovCloud support
in `aws-cloud-security-toolbox` and the `fedramp-*-library` repos.

## License

MIT — see [LICENSE](LICENSE).
