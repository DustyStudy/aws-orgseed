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
  value = try(aws_cloudtrail.baseline[0].arn, null)
}

output "scp_statement_sids" {
  description = "The Sids of the statements in the baseline SCP - what it actually enforces. Used by the Phase 1 proof report."
  value       = sort([for s in data.aws_iam_policy_document.scp_baseline.statement : s.sid])
}

