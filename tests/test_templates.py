"""
Structural tests for the bootstrap CloudFormation templates, the Terraform
baseline and the seed workflow.

cfn-lint and checkov validate that these files are *well-formed*; they can't
tell you a policy is *wrong for how it is used*. These tests pin the specific
properties that were wrong (each one is a real failure mode against a live
org, not a style point), so a refactor can't quietly reintroduce them.

Runs without AWS: it only parses the files.
"""
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
BOOTSTRAP = ROOT / "bootstrap"


class _CfnLoader(yaml.SafeLoader):
    """SafeLoader that understands CloudFormation's short-form tags (!Ref, !Sub, ...)."""


def _cfn_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    return {"Ref": value} if tag_suffix == "Ref" else {f"Fn::{tag_suffix}": value}


_CfnLoader.add_multi_constructor("!", _cfn_tag)


def load_template(name: str) -> dict:
    return yaml.load((BOOTSTRAP / name).read_text(), Loader=_CfnLoader)


def policy_statements(template: dict, role: str, policy_name: str) -> list[dict]:
    policies = template["Resources"][role]["Properties"]["Policies"]
    return next(p for p in policies if p["PolicyName"] == policy_name)["PolicyDocument"]["Statement"]


def statement(statements: list[dict], sid: str) -> dict:
    return next(s for s in statements if s.get("Sid") == sid)


def as_list(value):
    return value if isinstance(value, list) else [value]


@pytest.fixture(scope="module")
def roles_template():
    return load_template("org-seeding-role.yaml")


# ---------------------------------------------------------------------------
# TerraformCI: state locking
# ---------------------------------------------------------------------------

def test_ci_role_can_release_s3_native_state_locks(roles_template):
    """The generated backend.tf uses use_lockfile = true. S3-native locking
    creates <key>.tflock and DELETES it on unlock; without s3:DeleteObject the
    lock is never released and every later run is blocked."""
    stmts = policy_statements(roles_template, "TerraformCiRole", "orgseed-terraform-state-access")
    deletes = [s for s in stmts if s["Effect"] == "Allow" and "s3:DeleteObject" in as_list(s["Action"])]
    assert deletes, "TerraformCI needs s3:DeleteObject to release S3-native state locks"


def test_ci_role_can_only_delete_lock_files_not_state(roles_template):
    """Deleting the lock file is needed; deleting the state itself is not."""
    stmts = policy_statements(roles_template, "TerraformCiRole", "orgseed-terraform-state-access")
    for s in stmts:
        if s["Effect"] == "Allow" and "s3:DeleteObject" in as_list(s["Action"]):
            for resource in as_list(s["Resource"]):
                arn = resource["Fn::Sub"] if isinstance(resource, dict) else resource
                assert arn.endswith("/*.tflock"), f"s3:DeleteObject must be limited to *.tflock, got {arn}"


# ---------------------------------------------------------------------------
# TerraformCI: Organizations calls are global
# ---------------------------------------------------------------------------

def test_organizations_writes_are_not_pinned_to_the_stack_region(roles_template):
    """Organizations is a global service served from us-east-1 (us-gov-west-1
    in GovCloud), so aws:RequestedRegion is that region for its calls - not
    whatever region the bootstrap stack happens to live in."""
    stmts = policy_statements(roles_template, "TerraformCiRole", "orgseed-guardrail-baseline")
    cond = statement(stmts, "OrganizationsUnscopableWrites")["Condition"]["StringEquals"]["aws:RequestedRegion"]
    assert cond != {"Ref": "AWS::Region"}, "Organizations calls must not be pinned to the stack's own region"
    assert "Fn::If" in cond, "expected a partition-dependent region (us-east-1 vs us-gov-west-1)"


def test_config_writes_stay_pinned_to_the_stack_region(roles_template):
    """Config, unlike Organizations, is regional - the pin is correct there."""
    stmts = policy_statements(roles_template, "TerraformCiRole", "orgseed-guardrail-baseline")
    cond = statement(stmts, "ConfigUnscopableWrites")["Condition"]["StringEquals"]["aws:RequestedRegion"]
    assert cond == {"Ref": "AWS::Region"}


# ---------------------------------------------------------------------------
# TerraformCI: what aws_cloudtrail actually calls
# ---------------------------------------------------------------------------

def test_ci_role_has_the_cloudtrail_reads_terraform_needs(roles_template):
    """aws_cloudtrail reads event selectors, insight selectors and tags on every
    refresh; a policy lacking them fails with AccessDenied on the second plan."""
    stmts = policy_statements(roles_template, "TerraformCiRole", "orgseed-guardrail-baseline")
    allowed = {a for s in stmts if s["Effect"] == "Allow" for a in as_list(s["Action"])}
    for action in ("cloudtrail:GetEventSelectors", "cloudtrail:GetInsightSelectors", "cloudtrail:ListTags"):
        assert action in allowed, f"missing {action}"


def test_ci_role_can_tag_its_trail(roles_template):
    """default_tags on the provider make CreateTrail carry tags, which needs AddTags."""
    stmts = policy_statements(roles_template, "TerraformCiRole", "orgseed-guardrail-baseline")
    allowed = {a for s in stmts if s["Effect"] == "Allow" for a in as_list(s["Action"])}
    assert "cloudtrail:AddTags" in allowed


# ---------------------------------------------------------------------------
# Hub OIDC provider: an account can only have one per issuer URL
# ---------------------------------------------------------------------------

def test_oidc_provider_can_reuse_an_existing_provider():
    t = load_template("oidc-provider.yaml")
    assert "ExistingOidcProviderArn" in t["Parameters"]
    assert t["Parameters"]["ExistingOidcProviderArn"]["Default"] == ""
    assert "CreateProvider" in t["Conditions"]
    assert t["Resources"]["GitHubOidcProvider"]["Condition"] == "CreateProvider"


def test_hub_role_trusts_whichever_provider_is_in_use():
    t = load_template("oidc-provider.yaml")
    principal = t["Resources"]["HubSeederRole"]["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]["Federated"]
    assert "Fn::If" in principal, "hub role must fall back to the existing provider ARN when one is supplied"


def test_hub_trust_is_pinned_to_the_seed_environment_by_default():
    """The seed workflow runs in a GitHub Environment (required reviewers), and
    a job with `environment:` presents sub = repo:o/r:environment:<name> - not
    ref:refs/heads/main. The default must match or the hub assume fails."""
    t = load_template("oidc-provider.yaml")
    assert t["Parameters"]["AllowedRef"]["Default"] == "environment:orgseed"


# ---------------------------------------------------------------------------
# Hub trust: GitHub's immutable OIDC subject format
# ---------------------------------------------------------------------------
# GitHub can emit `sub` as repo:OWNER@OWNER_ID/REPO@REPO_ID:<suffix> (the
# `use_immutable_subject` repo setting - true for every repo created recently).
# A trust condition written for the classic repo:OWNER/REPO:<suffix> form then
# never matches, and the hub role can never be assumed from GitHub Actions.

def _hub_sub_condition(t):
    doc = t["Resources"]["HubSeederRole"]["Properties"]["AssumeRolePolicyDocument"]
    return doc["Statement"][0]["Condition"]["StringLike"]["token.actions.githubusercontent.com:sub"]


def test_hub_trust_defaults_to_the_immutable_subject_format():
    t = load_template("oidc-provider.yaml")
    assert t["Parameters"]["SubjectFormat"]["Default"] == "immutable"
    assert set(t["Parameters"]["SubjectFormat"]["AllowedValues"]) == {"immutable", "classic"}
    cond = _hub_sub_condition(t)
    assert "Fn::If" in cond, "trust must branch on the subject format"
    branch, immutable, classic = cond["Fn::If"]
    assert branch == "UseImmutableSubject"
    assert immutable["Fn::Sub"] == "repo:${GitHubOrg}@${GitHubOrgId}/${GitHubRepo}@${GitHubRepoId}:${AllowedRef}"
    assert classic["Fn::Sub"] == "repo:${GitHubOrg}/${GitHubRepo}:${AllowedRef}"


def test_hub_trust_pins_exact_ids_not_a_wildcard():
    """Owner/repo IDs are immutable, so a renamed, deleted or re-created repo
    cannot impersonate this one. Do not weaken to `@*`."""
    cond = _hub_sub_condition(load_template("oidc-provider.yaml"))
    assert "@*" not in str(cond)


def test_immutable_format_requires_both_ids_at_stack_creation():
    """Fail fast with instructions rather than deploying a trust that silently
    never matches."""
    t = load_template("oidc-provider.yaml")
    assert t["Parameters"]["GitHubOrgId"]["Default"] == ""
    assert t["Parameters"]["GitHubRepoId"]["Default"] == ""
    assert t["Parameters"]["GitHubOrgId"]["AllowedPattern"] == "^[0-9]*$"
    rule = next(iter(t["Rules"].values()))
    assert rule["RuleCondition"] == {"Fn::Equals": [{"Ref": "SubjectFormat"}, "immutable"]}
    messages = " ".join(a["AssertDescription"] for a in rule["Assertions"])
    assert "gh api" in messages, "the error should say how to look the IDs up"


# ---------------------------------------------------------------------------
# State backend safety
# ---------------------------------------------------------------------------

def test_state_bucket_survives_stack_deletion_and_replacement():
    t = load_template("state-backend.yaml")
    bucket = t["Resources"]["StateBucket"]
    assert bucket["DeletionPolicy"] == "Retain"
    assert bucket["UpdateReplacePolicy"] == "Retain"


def test_every_stateful_resource_states_its_deletion_policy():
    """cfn-lint I3011: leaving DeletionPolicy/UpdateReplacePolicy to the default
    (Delete) should be a decision, not an omission."""
    t = load_template("state-backend.yaml")
    for name in ("StateBucket", "LockTable"):
        res = t["Resources"][name]
        assert "DeletionPolicy" in res and "UpdateReplacePolicy" in res, f"{name} must state both policies explicitly"
    assert t["Resources"]["LockTable"]["DeletionPolicy"] == "Delete", "lock records are transient; only the state bucket is retained"


# ---------------------------------------------------------------------------
# Terraform baseline
# ---------------------------------------------------------------------------

def _tf(name: str) -> str:
    return (ROOT / "modules" / "org-baseline" / name).read_text()


def test_scp_does_not_hardcode_the_ci_role_name():
    """ci_role_name is configurable in orgs.yaml; an SCP exempting a literal
    'orgseed-ci' would silently deny a renamed CI role."""
    scp = _tf("scp.tf")
    assert 'variable "ci_role_name"' in scp
    assert "role/orgseed-ci" not in scp


def test_scp_imdsv2_resource_follows_the_partition():
    scp = _tf("scp.tf")
    assert "arn:aws:ec2" not in scp, "hard-coded partition breaks GovCloud"
    assert "var.partition" in scp


def test_imdsv2_enforcement_can_be_turned_off():
    """It blocks any launch template that doesn't require IMDSv2 - keep it on by
    default, but let an org with legacy launches stage the rollout."""
    assert 'variable "enforce_imdsv2"' in _tf("scp.tf")


def test_trail_is_account_scoped_unless_org_trail_requested():
    ct = _tf("cloudtrail.tf")
    assert 'variable "is_organization_trail"' in ct
    assert re.search(r"is_organization_trail\s*=\s*var\.is_organization_trail", ct)


# ---------------------------------------------------------------------------
# Seed workflow
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def seed_workflow():
    return yaml.safe_load((ROOT / ".github" / "workflows" / "seed.yml").read_text())


def test_seed_workflow_requires_an_environment(seed_workflow):
    """The only thing between a push to main and org-management admin is this gate."""
    assert seed_workflow["jobs"]["seed"]["environment"] == "orgseed"


def test_seed_workflow_does_not_interpolate_inputs_into_the_shell(seed_workflow):
    for step in seed_workflow["jobs"]["seed"]["steps"]:
        assert "${{ inputs" not in step.get("run", ""), "workflow_dispatch inputs must go through env vars, not the script text"


def _seed_step(seed_workflow):
    return next(s for s in seed_workflow["jobs"]["seed"]["steps"] if s.get("name") == "Run seed.py")


def test_seed_workflow_reads_the_org_config_from_a_secret_not_a_variable(seed_workflow):
    """Real account IDs and bucket names must not be committed to a public repo,
    and must not be printed into a public workflow log either. GitHub masks
    *secrets* in logs but prints *variables* (and every step's env) in the clear,
    so the config lives in a secret, stored base64 (a single line masks reliably,
    where a multi-line value is masked line by line)."""
    step = _seed_step(seed_workflow)
    assert step["env"]["ORGSEED_CONFIG"] == "${{ secrets.ORGSEED_CONFIG }}"
    run = step["run"]
    assert "base64 -d" in run and "RUNNER_TEMP" in run
    assert "cli/orgs.yaml" in run, "must still fall back to the committed example config"
    # goes through the environment into a file - never interpolated into the script text
    assert "${{ secrets" not in run and "${{ vars" not in run


def test_seed_workflow_masks_identifiers_before_seed_py_can_print_them(seed_workflow):
    """seed.py prints the management account ID; masking must precede it."""
    run = _seed_step(seed_workflow)["run"]
    assert "::add-mask::" in run
    assert run.index("::add-mask::") < run.index("python cli/seed.py")


def test_seed_workflow_trust_refs_come_from_secrets_only(seed_workflow):
    env = _seed_step(seed_workflow)["env"]
    refs = {k: v for k, v in env.items() if k.startswith("ORGSEED_TRUST_")}
    assert refs, "at least one per-org ExternalId must actually be mapped, or seed.py refuses to run"
    for name, value in refs.items():
        assert value == "${{ secrets." + name + " }}", f"{name} must come from a secret, never a variable or literal"


def test_seed_workflow_hub_role_arn_is_a_secret(seed_workflow):
    """The hub role ARN contains the hub account ID, and a step's `with:` inputs
    are printed in the log. As a variable it appears in the clear; as a secret it
    is masked."""
    step = next(s for s in seed_workflow["jobs"]["seed"]["steps"] if s.get("name", "").startswith("Configure AWS credentials"))
    assert step["with"]["role-to-assume"] == "${{ secrets.ORGSEED_HUB_ROLE_ARN }}"

