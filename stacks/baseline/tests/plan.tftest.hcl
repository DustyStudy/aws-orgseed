# Mocked-provider tests for the Phase 1 root stack. No AWS account or credentials.

mock_provider "aws" {
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

variables {
  org_alias     = "sandbox"
  scp_target_id = "ou-abcd-12345678"
}

run "plans_the_scp_only" {
  command = plan

  assert {
    condition     = module.baseline.cloudtrail_arn == null
    error_message = "Phase 1 applies the SCP only; the trail needs five resources that don't exist yet."
  }

  assert {
    condition     = length(module.baseline.scp_statement_sids) == 5
    error_message = "All five guardrails should be in the SCP by default."
  }
}

run "imdsv2_can_be_staged_off_from_the_stack" {
  command = plan

  variables {
    enforce_imdsv2 = false
  }

  assert {
    condition     = !contains(module.baseline.scp_statement_sids, "RequireImdsv2OnLaunch")
    error_message = "enforce_imdsv2 = false must drop the IMDSv2 guardrail and nothing else."
  }

  assert {
    condition     = length(module.baseline.scp_statement_sids) == 4
    error_message = "The other four guardrails must remain."
  }
}

run "the_stack_can_never_target_the_org_root" {
  command = plan

  variables {
    scp_target_id = "r-abcd"
  }

  expect_failures = [var.scp_target_id]
}

run "rejects_a_malformed_target" {
  command = plan

  variables {
    scp_target_id = "not-an-id"
  }

  expect_failures = [var.scp_target_id]
}
