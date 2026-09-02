# modules/ci-role
#
# Optional Phase 1 module: once an org is bootstrapped, use this to compute
# and inspect the trust policy the TerraformCI role should have (e.g. after
# narrowing ci_trust_ref, or adding a second environment). Import the actual
# aws_iam_role resource here once you're ready to manage it via Terraform
# instead of the CFN bootstrap stack.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "ci_role_name" {
  type = string
}

variable "hub_role_arn" {
  type = string
}

data "aws_iam_policy_document" "trust" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.hub_role_arn]
    }
  }
}

output "trust_policy_json" {
  description = "Trust policy the TerraformCI role should have -- diff against the live role before importing"
  value       = data.aws_iam_policy_document.trust.json
}

output "target_role_name" {
  description = "Role this trust policy is intended for, once imported"
  value       = var.ci_role_name
}
