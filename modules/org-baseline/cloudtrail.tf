# modules/org-baseline/cloudtrail.tf
#
# Points at centrally-managed resources rather than creating them here, same
# pattern as cloudtrail_log_bucket below:
#   - cloudtrail_log_bucket        S3 bucket, already policy-configured to
#                                  accept CloudTrail log delivery
#   - cloudtrail_kms_key_arn       KMS CMK for encrypting the trail's log
#                                  files at rest (CKV_AWS_35)
#   - cloudtrail_sns_topic_name    SNS topic CloudTrail notifies on each new
#                                  log file delivery (CKV_AWS_252)
#   - cloudtrail_log_group_arn /
#     cloudtrail_cloudwatch_role_arn
#                                  CloudWatch Logs group + the role CloudTrail
#                                  assumes to write to it (CKV2_AWS_10)
#
# All four are expected to already exist, managed by aws-cloud-security-toolbox
# or aws-observability-dashboards, not by this module. TerraformCiRole's IAM
# policy grants nothing on S3/KMS/SNS/CloudWatch Logs beyond a narrowly-scoped
# iam:PassRole for the CloudWatch delivery role specifically (see
# bootstrap/org-seeding-role.yaml's CloudTrailCloudWatchDelivery statement) --
# CloudTrail itself, not Terraform, does the actual writing to these
# resources, using permissions granted by their own resource policies.
#
# cloudtrail_cloudwatch_role_arn must match the naming convention
# role/orgseed-cwl-delivery-* -- that's what TerraformCiRole's scoped
# iam:PassRole statement allows. Provision the role once under that name,
# following AWS's standard CloudTrail-to-CloudWatch-Logs trust policy.

variable "create_cloudtrail" {
  type        = bool
  default     = true
  description = <<-EOT
    Create the baseline trail. The trail needs five resources that must already
    exist (log bucket, KMS key, SNS topic, CloudWatch Logs group + delivery role -
    see above), so set false to apply the SCP on its own. When true, all five
    cloudtrail_* variables are required.
  EOT

  validation {
    condition = !var.create_cloudtrail || alltrue([
      var.cloudtrail_log_bucket != null,
      var.cloudtrail_kms_key_arn != null,
      var.cloudtrail_sns_topic_name != null,
      var.cloudtrail_log_group_arn != null,
      var.cloudtrail_cloudwatch_role_arn != null,
    ])
    error_message = "create_cloudtrail is true, so cloudtrail_log_bucket, cloudtrail_kms_key_arn, cloudtrail_sns_topic_name, cloudtrail_log_group_arn and cloudtrail_cloudwatch_role_arn are all required (or set create_cloudtrail = false to apply the SCP on its own)."
  }
}

variable "cloudtrail_log_bucket" {
  type        = string
  default     = null
  description = "Name of an existing S3 bucket, already policy-configured to accept CloudTrail log delivery, to send this org's trail to"
}

variable "cloudtrail_kms_key_arn" {
  type        = string
  default     = null
  description = "ARN of an existing KMS CMK used to encrypt this trail's log files at rest"
}

variable "cloudtrail_sns_topic_name" {
  type        = string
  default     = null
  description = "Name of an existing SNS topic, already policy-configured to accept CloudTrail notifications, to notify on each log file delivery"
}

variable "cloudtrail_log_group_arn" {
  type        = string
  default     = null
  description = "ARN of an existing CloudWatch Logs log group (include the trailing :* wildcard AWS expects) to stream this trail's events to"
}

variable "cloudtrail_cloudwatch_role_arn" {
  type        = string
  default     = null
  description = "ARN of the existing IAM role CloudTrail assumes to write to cloudtrail_log_group_arn -- must match role/orgseed-cwl-delivery-* (see bootstrap/org-seeding-role.yaml)"
}

variable "is_organization_trail" {
  type        = bool
  default     = false
  description = <<-EOT
    false (default): the trail records only THIS account's events - the
    management account's own activity. It does not cover member accounts.
    true: an organization trail that records every member account too. It needs,
    beforehand and outside this module: CloudTrail trusted access enabled for the
    org (organizations:EnableAWSServiceAccess for cloudtrail.amazonaws.com), the
    log bucket policy allowing delivery under the org ID path, and the
    TerraformCI role granted the extra permissions organization trails require.
    Left off by default because turning it on without those fails at apply.
  EOT
}

# checkov's CKV2_AWS_10 (CloudWatch Logs integration) is suppressed for this
# resource in .checkov.yaml at the repo root, not with an inline comment --
# CKV2_AWS_10 is a graph check, and graph checks don't honor inline
# #checkov:skip= comments. See .checkov.yaml for why this is a checkov
# resolution limitation and not an actual missing control.
resource "aws_cloudtrail" "baseline" {
  count = var.create_cloudtrail ? 1 : 0

  name                          = "orgseed-${var.org_alias}"
  s3_bucket_name                = var.cloudtrail_log_bucket
  kms_key_id                    = var.cloudtrail_kms_key_arn
  sns_topic_name                = var.cloudtrail_sns_topic_name
  cloud_watch_logs_group_arn    = var.cloudtrail_log_group_arn
  cloud_watch_logs_role_arn     = var.cloudtrail_cloudwatch_role_arn
  is_multi_region_trail         = true
  is_organization_trail         = var.is_organization_trail
  include_global_service_events = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}
