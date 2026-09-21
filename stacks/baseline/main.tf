# Phase 1 root stack: applies modules/org-baseline (the guardrail SCP) to ONE
# organizational unit, as the orgseed-ci role, from the terraform workflow.
#
# Deliberately thin, and deliberately incapable of:
#   - targeting the organization root (scp_target_id is validated as an OU ID and
#     the module's allow_root_target is never set) - a Deny SCP on the root hits
#     every member account at once, and only the management account can undo it;
#   - creating a CloudTrail trail (create_cloudtrail = false) - that needs a log
#     bucket, KMS key, SNS topic, log group and delivery role that are provisioned
#     elsewhere, and is not needed to apply or prove the SCP.
#
# Nothing account-specific is committed here. The workflow renders backend.hcl and
# terraform.tfvars.json at run time from the masked ORGSEED_CONFIG secret.

terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 7.0"
    }
  }

  # Partial backend: bucket/key/region/lock come from `-backend-config=backend.hcl`,
  # rendered from the org config so no account IDs or bucket names live in git.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region
  # Credentials come from the environment: the workflow chains
  # GitHub OIDC -> orgseed-hub -> orgseed-ci. No keys, no profiles.
}

module "baseline" {
  source = "../../modules/org-baseline"

  org_alias      = var.org_alias
  partition      = var.partition
  scp_target_id  = var.scp_target_id
  ci_role_name   = var.ci_role_name
  enforce_imdsv2 = var.enforce_imdsv2

  create_cloudtrail = false
}
