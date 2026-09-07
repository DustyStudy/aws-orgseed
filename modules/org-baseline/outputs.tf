# modules/org-baseline/outputs.tf

output "org_alias" {
  value = var.org_alias
}

output "partition" {
  value = var.partition
}

output "scp_policy_id" {
  description = "Organizations policy ID of the baseline SCP -- useful when attaching it to additional OUs outside this module"
  value       = aws_organizations_policy.baseline.id
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.baseline.arn
}
