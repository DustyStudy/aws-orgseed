# modules/org-baseline/scp.tf
#
# A small, deliberately conservative baseline SCP. Each statement is one a
# real org would actually turn on day one -- this is not a placeholder.
# Extend it in scp_baseline_document below rather than adding a second SCP,
# until you have a specific reason to split policies (SCPs are capped per
# target, so consolidating is the safer default).

variable "scp_target_id" {
  type        = string
  description = "Root or OU ID to attach the baseline SCP to (e.g. r-xxxx or ou-xxxx-xxxxxxxx)"
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
      values = ["arn:*:iam::*:role/orgseed-ci"]
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
      values   = ["arn:*:iam::*:role/orgseed-ci"]
    }
  }

  statement {
    sid       = "RequireImdsv2OnLaunch"
    effect    = "Deny"
    actions   = ["ec2:RunInstances"]
    resources = ["arn:aws:ec2:*:*:instance/*"]
    condition {
      test     = "StringNotEquals"
      variable = "ec2:MetadataHttpTokens"
      values   = ["required"]
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
