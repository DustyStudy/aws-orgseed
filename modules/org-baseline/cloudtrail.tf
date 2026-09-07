# modules/org-baseline/cloudtrail.tf
#
# Points at a centrally-managed log bucket rather than creating one here.
# TerraformCiRole's policy grants cloudtrail:CreateTrail/UpdateTrail/
# PutEventSelectors/StartLogging scoped to trail/orgseed-* (see
# bootstrap/org-seeding-role.yaml) but deliberately grants nothing on S3
# beyond the tfstate-* bucket -- the destination bucket's policy (allowing
# CloudTrail to write to it) is expected to already exist, managed by
# aws-cloud-security-toolbox or aws-observability-dashboards, not by this
# module. If you don't have one yet, create it there first.

variable "cloudtrail_log_bucket" {
  type        = string
  description = "Name of an existing S3 bucket, already policy-configured to accept CloudTrail log delivery, to send this org's trail to"
}

resource "aws_cloudtrail" "baseline" {
  name                          = "orgseed-${var.org_alias}"
  s3_bucket_name                = var.cloudtrail_log_bucket
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }
}
