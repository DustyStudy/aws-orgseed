# modules/org-baseline
#
# Phase 1 module: applies the guardrail baseline to a freshly-seeded org,
# authenticated via the TerraformCI role created in bootstrap/org-seeding-role.yaml.
#
# Intentionally left as a thin scaffold -- wire in SCPs, CloudTrail, and Config
# modules from aws-cloud-security-toolbox here rather than duplicating them.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "org_alias" {
  type        = string
  description = "Matches the alias in cli/orgs.yaml"
}

variable "partition" {
  type        = string
  default     = "aws"
  description = "aws or aws-us-gov"
}

# Example wiring point:
# module "scp_guardrails" {
#   source    = "git::https://github.com/DustyStudy/aws-cloud-security-toolbox//terraform/scp-guardrails"
#   org_alias = var.org_alias
#   partition = var.partition
# }
