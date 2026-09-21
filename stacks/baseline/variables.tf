variable "org_alias" {
  description = "Matches the alias in the org config."
  type        = string
}

variable "scp_target_id" {
  description = "OU to attach the baseline SCP to (ou-xxxx-xxxxxxxx). The org root is not accepted by this stack, by design."
  type        = string

  validation {
    condition     = can(regex("^ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}$", var.scp_target_id))
    error_message = "scp_target_id must be an OU ID (ou-xxxx-xxxxxxxx). This stack never targets the organization root."
  }
}

variable "partition" {
  type    = string
  default = "aws"
}

variable "aws_region" {
  description = "Region for the provider. Organizations is a global service served from us-east-1 (us-gov-west-1 in GovCloud)."
  type        = string
  default     = "us-east-1"
}

variable "ci_role_name" {
  description = "The TerraformCI role (ci_role_name in the org config); exempted from the CloudTrail/Config deny statements."
  type        = string
  default     = "orgseed-ci"
}

variable "enforce_imdsv2" {
  description = "Deny ec2:RunInstances unless IMDSv2 is required. Stage off first if you have legacy launches."
  type        = bool
  default     = true
}
