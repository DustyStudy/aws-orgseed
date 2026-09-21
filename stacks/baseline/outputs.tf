output "scp_policy_id" {
  description = "ID of the baseline SCP."
  value       = module.baseline.scp_policy_id
}

output "scp_statement_sids" {
  description = "What the SCP enforces."
  value       = module.baseline.scp_statement_sids
}
