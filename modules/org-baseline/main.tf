# modules/org-baseline
#
# Phase 1 module: applies the guardrail baseline to a freshly-seeded org,
# authenticated via the TerraformCI role created in
# bootstrap/org-seeding-role.yaml. TerraformCiRole's IAM policy is scoped
# to exactly the actions this module (and its two resource files, scp.tf
# and cloudtrail.tf) actually call -- if you extend this module, extend
# that policy too, in the same PR.
#
# Config baseline and IAM Identity Center wiring are intentionally left
# as TODOs (see the bottom of this file) rather than half-implemented --
# TerraformCiRole already carries the necessary permissions
# (config:Put*/Describe*, sso:*/identitystore:* read-only) for when you do.

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

# --- Still TODO, not wired up yet ---
#
# AWS Config baseline (recorder + delivery channel + a couple of managed
# rules). TerraformCiRole already has config:Put*/Describe* -- see
# bootstrap/org-seeding-role.yaml's ConfigUnscopableWrites /ConfigReadOnly
# statements -- so this is purely "write the resources", not a permissions
# change.
#
# IAM Identity Center baseline (permission sets, account assignments).
# TerraformCiRole currently only has read-only sso:*/identitystore:*
# actions; granting write access here is a deliberate follow-up, not an
# oversight -- Identity Center changes affect who can log in at all, so
# they deserve their own PR and their own review, not a silent addition
# to the general guardrail policy.
