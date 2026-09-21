# Mocked-provider tests: no AWS account or credentials. They check the
# configuration that feeds the SCP and trail (statement set, ARNs, exemption
# role name), not how AWS evaluates it.

mock_provider "aws" {
  # The provider validates the SCP body as JSON; the default mock's random
  # string would fail that before any assertion runs.
  mock_data "aws_iam_policy_document" {
    defaults = { json = "{}" }
  }
}

variables {
  org_alias                      = "acme"
  scp_target_id                  = "ou-abcd-12345678"
  cloudtrail_log_bucket          = "acme-cloudtrail-logs"
  cloudtrail_kms_key_arn         = "arn:aws:kms:us-east-1:222222222222:key/11111111-1111-1111-1111-111111111111"
  cloudtrail_sns_topic_name      = "acme-cloudtrail"
  cloudtrail_log_group_arn       = "arn:aws:logs:us-east-1:222222222222:log-group:cloudtrail:*"
  cloudtrail_cloudwatch_role_arn = "arn:aws:iam::222222222222:role/orgseed-cwl-delivery-acme"
}

run "default_scp_has_all_five_guardrails" {
  command = plan

  assert {
    condition     = length(data.aws_iam_policy_document.scp_baseline.statement) == 5
    error_message = "Expected leave-org, CloudTrail, Config, IMDSv2 and root-user statements."
  }
}

run "imdsv2_can_be_staged_off" {
  command = plan

  variables {
    enforce_imdsv2 = false
  }

  assert {
    condition     = length(data.aws_iam_policy_document.scp_baseline.statement) == 4
    error_message = "enforce_imdsv2 = false must drop the IMDSv2 deny and nothing else."
  }

  assert {
    condition     = !contains([for s in data.aws_iam_policy_document.scp_baseline.statement : s.sid], "RequireImdsv2OnLaunch")
    error_message = "IMDSv2 statement should be gone."
  }
}

run "imdsv2_resource_follows_partition" {
  command = plan

  variables {
    partition = "aws-us-gov"
  }

  assert {
    condition     = one([for s in data.aws_iam_policy_document.scp_baseline.statement : s if s.sid == "RequireImdsv2OnLaunch"]).resources == toset(["arn:aws-us-gov:ec2:*:*:instance/*"])
    error_message = "GovCloud must use arn:aws-us-gov, not a hard-coded arn:aws."
  }
}

run "ci_exemption_uses_the_configured_role_name" {
  command = plan

  variables {
    ci_role_name = "my-renamed-ci"
  }

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.scp_baseline.statement :
      contains(["DenyDisablingCloudTrail", "DenyDisablingConfig"], s.sid) ? one(one(s.condition).values) == "arn:*:iam::*:role/my-renamed-ci" : true
    ])
    error_message = "The CloudTrail/Config exemption must follow ci_role_name, or the SCP denies the renamed CI role."
  }
}

run "trail_is_account_scoped_by_default" {
  command = plan

  assert {
    condition     = aws_cloudtrail.baseline[0].is_organization_trail == false && aws_cloudtrail.baseline[0].is_multi_region_trail == true
    error_message = "Default trail must be multi-region, account-scoped (org trail is opt-in)."
  }
}

run "org_trail_is_opt_in" {
  command = plan

  variables {
    is_organization_trail = true
  }

  assert {
    condition     = aws_cloudtrail.baseline[0].is_organization_trail == true
    error_message = "is_organization_trail should reach the trail."
  }
}

# --- Phase 1: the SCP must be usable on its own, and safe to point somewhere ---------

run "scp_only_needs_no_cloudtrail_dependencies" {
  command = plan

  variables {
    create_cloudtrail              = false
    cloudtrail_log_bucket          = null
    cloudtrail_kms_key_arn         = null
    cloudtrail_sns_topic_name      = null
    cloudtrail_log_group_arn       = null
    cloudtrail_cloudwatch_role_arn = null
  }

  assert {
    condition     = length(aws_cloudtrail.baseline) == 0
    error_message = "create_cloudtrail = false must create no trail (the five supporting resources need not exist)."
  }

  assert {
    condition     = output.cloudtrail_arn == null
    error_message = "cloudtrail_arn should be null when no trail is created."
  }
}

run "cloudtrail_stays_the_default" {
  command = plan

  assert {
    condition     = length(aws_cloudtrail.baseline) == 1
    error_message = "Existing behaviour must not change: the trail is created unless turned off."
  }
}

run "trail_requires_all_five_dependencies_when_enabled" {
  command = plan

  variables {
    cloudtrail_kms_key_arn = null
  }

  expect_failures = [var.create_cloudtrail]
}

run "refuses_the_org_root_by_default" {
  command = plan

  variables {
    scp_target_id = "r-abcd"
  }

  expect_failures = [var.scp_target_id]
}

run "root_is_possible_only_when_explicitly_allowed" {
  command = plan

  variables {
    scp_target_id     = "r-abcd"
    allow_root_target = true
  }

  assert {
    condition     = aws_organizations_policy_attachment.baseline.target_id == "r-abcd"
    error_message = "allow_root_target = true should permit attaching to the root."
  }
}

run "rejects_a_target_that_is_neither_ou_nor_root" {
  command = plan

  variables {
    scp_target_id = "123456789012"
  }

  expect_failures = [var.scp_target_id]
}

run "outputs_list_what_the_scp_enforces" {
  command = plan

  assert {
    condition     = output.scp_statement_sids == tolist(["DenyDisablingCloudTrail", "DenyDisablingConfig", "DenyLeaveOrganization", "DenyRootUserActions", "RequireImdsv2OnLaunch"])
    error_message = "The output should list exactly the five guardrails."
  }
}

