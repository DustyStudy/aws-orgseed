# modules/org-baseline/scp.tf
#
# A small, deliberately conservative baseline SCP. Each statement is one a
# real org would actually turn on day one -- this is not a placeholder.
# Extend it in scp_baseline_document below rather than adding a second SCP,
# until you have a specific reason to split policies (SCPs are capped per
# target, so consolidating is the safer default).

# NOTE: SCPs never apply to the organization's management account - only to
# member accounts. Attaching this to the root protects every member account and
# leaves the management account itself governed by IAM alone. Trial it on an OU
# before the root: a Deny SCP that is too broad locks people out, and only the
# management account can undo it.

variable "scp_target_id" {
  type        = string
  description = "Root or OU ID to attach the baseline SCP to (e.g. r-xxxx or ou-xxxx-xxxxxxxx)"
}

variable "ci_role_name" {
  type        = string
  default     = "orgseed-ci"
  description = "Name of the TerraformCI role (cli/orgs.yaml's ci_role_name). Exempted from the CloudTrail/Config deny statements so it can manage what it created. Must match, or the SCP denies your own CI."
}

variable "enforce_imdsv2" {
  type        = bool
  default     = true
  description = "Deny ec2:RunInstances unless IMDSv2 is required. Blocks ANY launch (including launch templates, ASGs, Karpenter, managed node groups) that leaves HttpTokens optional, so set false first if you have legacy launches, fix them, then turn it on."
}

data "aws_iam_policy_document" "scp_baseline" {
  statement {
    sid       = "DenyLeaveOrganization"
    effect    = "Deny"
    actions   = ["organizations:LeaveOrganization"]
    resources = ["*"]
  }

  statement {
    sid    = "DenyDisablingCloudTrail"
    effect = "Deny"
    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      # The TerraformCI role itself is exempt so this module can still
      # manage the trail it creates in cloudtrail.tf.
      values = ["arn:*:iam::*:role/${var.ci_role_name}"]
    }
  }

  statement {
    sid    = "DenyDisablingConfig"
    effect = "Deny"
    actions = [
      "config:DeleteConfigurationRecorder",
      "config:DeleteDeliveryChannel",
      "config:StopConfigurationRecorder",
    ]
    resources = ["*"]
    condition {
      test     = "StringNotLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:*:iam::*:role/${var.ci_role_name}"]
    }
  }

  dynamic "statement" {
    for_each = var.enforce_imdsv2 ? [1] : []
    content {
      sid       = "RequireImdsv2OnLaunch"
      effect    = "Deny"
      actions   = ["ec2:RunInstances"]
      resources = ["arn:${var.partition}:ec2:*:*:instance/*"]
      condition {
        test     = "StringNotEquals"
        variable = "ec2:MetadataHttpTokens"
        values   = ["required"]
      }
    }
  }

  statement {
    sid    = "DenyRootUserActions"
    effect = "Deny"
    actions = [
      "iam:CreateAccessKey",
      "iam:CreateUser",
      "iam:UpdateLoginProfile",
    ]
    resources = ["*"]
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:*:iam::*:root"]
    }
  }
}

resource "aws_organizations_policy" "baseline" {
  name        = "orgseed-${var.org_alias}-baseline"
  description = "Baseline guardrails applied by aws-orgseed's org-baseline module. Edit scp.tf, not the AWS console."
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.scp_baseline.json
}

resource "aws_organizations_policy_attachment" "baseline" {
  policy_id = aws_organizations_policy.baseline.id
  target_id = var.scp_target_id
}
