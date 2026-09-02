# modules/ci-role
#
# Optional Phase 1 module: once an org is bootstrapped, use this to adjust
# the TerraformCI role's trust policy (e.g. narrow ci_trust_ref, add a
# second environment) without re-running the CFN bootstrap stack.

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

resource "aws_iam_role_policy_attachment" "trust_update" {
  # Placeholder -- replace with aws_iam_role assume_role_policy management
  # once this org's baseline permission set (vs. AdministratorAccess) is decided.
  count      = 0
  role       = var.ci_role_name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}
