"""
Unit tests for cli/seed.py.

Deliberately avoids moto/networked AWS mocking: seed.py is a thin
orchestration layer over three boto3 calls (describe_stacks, create_stack /
update_stack, assume_role) plus local file writing, so a plain
unittest.mock.MagicMock standing in for the boto3 client is enough to
exercise its branching logic without adding a heavier test dependency.

Run with:
    pip install -r cli/requirements.txt -r cli/requirements-dev.txt
    pytest tests/
"""
from unittest.mock import MagicMock

import pytest

import seed


# ---------------------------------------------------------------------------
# validate_config
# ---------------------------------------------------------------------------

def _valid_org(**overrides):
    org = {
        "alias": "acme-commercial",
        "management_account_id": "222222222222",
        "partition": "aws",
        "regions": ["us-east-1"],
        "seeding_admin_role_name": "OrgSeedAdmin",
        "ci_role_name": "orgseed-ci",
        "state_bucket": "tfstate-acme-commercial",
        "ci_trust_ref": "some-secret-value",
    }
    org.update(overrides)
    return org


def _valid_config(orgs=None):
    return {
        "hub_account_id": "111111111111",
        "hub_role_arn": "arn:aws:iam::111111111111:role/orgseed-hub",
        "github_repo": "DustyStudy/aws-orgseed",
        "orgs": orgs if orgs is not None else [_valid_org()],
    }


def test_validate_config_accepts_a_valid_config():
    seed.validate_config(_valid_config())  # should not raise


@pytest.mark.parametrize("missing_key", seed.REQUIRED_TOP_LEVEL_KEYS)
def test_validate_config_rejects_missing_top_level_key(missing_key):
    config = _valid_config()
    del config[missing_key]
    with pytest.raises(ValueError, match=missing_key):
        seed.validate_config(config)


def test_validate_config_rejects_empty_orgs_list():
    config = _valid_config(orgs=[])
    with pytest.raises(ValueError, match="at least one org"):
        seed.validate_config(config)


@pytest.mark.parametrize("missing_key", seed.REQUIRED_ORG_KEYS)
def test_validate_config_rejects_org_missing_required_key(missing_key):
    org = _valid_org()
    del org[missing_key]
    config = _valid_config(orgs=[org])
    with pytest.raises(ValueError, match=missing_key):
        seed.validate_config(config)


def test_validate_config_rejects_duplicate_alias():
    config = _valid_config(orgs=[_valid_org(), _valid_org()])
    with pytest.raises(ValueError, match="duplicate org alias"):
        seed.validate_config(config)


def test_validate_config_rejects_empty_regions():
    config = _valid_config(orgs=[_valid_org(regions=[])])
    with pytest.raises(ValueError, match="at least one region"):
        seed.validate_config(config)


def test_validate_config_rejects_lock_table_true_without_name():
    config = _valid_config(orgs=[_valid_org(use_lock_table=True)])
    with pytest.raises(ValueError, match="lock_table"):
        seed.validate_config(config)


def test_validate_config_allows_lock_table_true_with_name():
    config = _valid_config(orgs=[_valid_org(use_lock_table=True, lock_table="tflock-acme")])
    seed.validate_config(config)  # should not raise


def test_validate_config_rejects_non_mapping_org():
    config = _valid_config(orgs=["not-a-dict"])
    with pytest.raises(TypeError, match="not a mapping"):
        seed.validate_config(config)


def test_validate_config_rejects_non_mapping_top_level():
    with pytest.raises(TypeError, match="mapping"):
        seed.validate_config(["not-a-dict"])


# ---------------------------------------------------------------------------
# partition_arn
# ---------------------------------------------------------------------------

def test_partition_arn_commercial():
    assert seed.partition_arn("222222222222", "aws", "OrgSeedAdmin") == (
        "arn:aws:iam::222222222222:role/OrgSeedAdmin"
    )


def test_partition_arn_govcloud():
    assert seed.partition_arn("333333333333", "aws-us-gov", "OrgSeedAdmin") == (
        "arn:aws-us-gov:iam::333333333333:role/OrgSeedAdmin"
    )


# ---------------------------------------------------------------------------
# assume_role
# ---------------------------------------------------------------------------

def _fake_sts_client(session_name_capture=None):
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AKIDEXAMPLE",
            "SecretAccessKey": "secret",
            "SessionToken": "token",
        }
    }
    return sts


def test_assume_role_passes_external_id_when_given(monkeypatch):
    sts = _fake_sts_client()
    fake_session = MagicMock()
    monkeypatch.setattr(seed.boto3, "Session", MagicMock(return_value=fake_session))

    result = seed.assume_role(sts, "arn:aws:iam::222222222222:role/OrgSeedAdmin", "my-session", external_id="trust-ref-123")

    sts.assume_role.assert_called_once_with(
        RoleArn="arn:aws:iam::222222222222:role/OrgSeedAdmin",
        RoleSessionName="my-session",
        ExternalId="trust-ref-123",
    )
    assert result is fake_session


def test_assume_role_omits_external_id_when_not_given(monkeypatch):
    sts = _fake_sts_client()
    monkeypatch.setattr(seed.boto3, "Session", MagicMock())

    seed.assume_role(sts, "arn:aws:iam::222222222222:role/OrgSeedAdmin", "my-session")

    _, kwargs = sts.assume_role.call_args
    assert "ExternalId" not in kwargs


def test_assume_role_builds_session_from_returned_credentials(monkeypatch):
    sts = _fake_sts_client()
    session_ctor = MagicMock()
    monkeypatch.setattr(seed.boto3, "Session", session_ctor)

    seed.assume_role(sts, "arn:aws:iam::222222222222:role/OrgSeedAdmin", "my-session")

    session_ctor.assert_called_once_with(
        aws_access_key_id="AKIDEXAMPLE",
        aws_secret_access_key="secret",
        aws_session_token="token",
    )


# ---------------------------------------------------------------------------
# deploy_stack
# ---------------------------------------------------------------------------

class FakeClientError(Exception):
    pass


def _fake_cfn_client():
    cfn = MagicMock()
    cfn.exceptions.ClientError = FakeClientError
    return cfn


def test_deploy_stack_creates_when_stack_does_not_exist(tmp_path):
    cfn = _fake_cfn_client()
    cfn.describe_stacks.side_effect = FakeClientError("does not exist")
    waiter = MagicMock()
    cfn.get_waiter.return_value = waiter

    template = tmp_path / "template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\n")

    seed.deploy_stack(cfn, "orgseed-roles-acme", template, {"OrgAlias": "acme"})

    cfn.create_stack.assert_called_once()
    cfn.update_stack.assert_not_called()
    cfn.get_waiter.assert_called_once_with("stack_create_complete")
    waiter.wait.assert_called_once_with(StackName="orgseed-roles-acme")


def test_deploy_stack_updates_when_stack_exists_with_changes(tmp_path):
    cfn = _fake_cfn_client()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackName": "orgseed-roles-acme"}]}
    waiter = MagicMock()
    cfn.get_waiter.return_value = waiter

    template = tmp_path / "template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\n")

    seed.deploy_stack(cfn, "orgseed-roles-acme", template, {"OrgAlias": "acme"})

    cfn.create_stack.assert_not_called()
    cfn.update_stack.assert_called_once()
    cfn.get_waiter.assert_called_once_with("stack_update_complete")
    waiter.wait.assert_called_once_with(StackName="orgseed-roles-acme")


def test_deploy_stack_no_op_when_no_changes(tmp_path):
    cfn = _fake_cfn_client()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackName": "orgseed-roles-acme"}]}
    cfn.update_stack.side_effect = FakeClientError("No updates are to be performed.")

    template = tmp_path / "template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\n")

    seed.deploy_stack(cfn, "orgseed-roles-acme", template, {"OrgAlias": "acme"})

    cfn.get_waiter.assert_not_called()


def test_deploy_stack_reraises_other_update_errors(tmp_path):
    cfn = _fake_cfn_client()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackName": "orgseed-roles-acme"}]}
    cfn.update_stack.side_effect = FakeClientError("Some other failure")

    template = tmp_path / "template.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\n")

    with pytest.raises(FakeClientError, match="Some other failure"):
        seed.deploy_stack(cfn, "orgseed-roles-acme", template, {"OrgAlias": "acme"})


# ---------------------------------------------------------------------------
# write_backend_tf
# ---------------------------------------------------------------------------

def test_write_backend_tf_uses_lockfile_by_default(tmp_path, monkeypatch):
    monkeypatch.setattr(seed, "OUTPUT_DIR", tmp_path)
    org = _valid_org()

    seed.write_backend_tf("acme-commercial", org)

    content = (tmp_path / "acme-commercial" / "backend.tf").read_text()
    assert 'bucket = "tfstate-acme-commercial"' in content
    assert "use_lockfile = true" in content
    assert "dynamodb_table" not in content


def test_write_backend_tf_uses_dynamodb_when_configured(tmp_path, monkeypatch):
    monkeypatch.setattr(seed, "OUTPUT_DIR", tmp_path)
    org = _valid_org(use_lock_table=True, lock_table="tflock-acme")

    seed.write_backend_tf("acme-commercial", org)

    content = (tmp_path / "acme-commercial" / "backend.tf").read_text()
    assert 'dynamodb_table = "tflock-acme"' in content
    assert "use_lockfile" not in content


# ---------------------------------------------------------------------------
# resolve_trust_ref
# ---------------------------------------------------------------------------

def test_resolve_trust_ref_returns_a_literal_value():
    assert seed.resolve_trust_ref(_valid_org(ci_trust_ref="s3cr3t-random")) == "s3cr3t-random"


def test_resolve_trust_ref_reads_env_indirection(monkeypatch):
    monkeypatch.setenv("ORGSEED_TRUST_ACME", "from-the-environment")
    assert seed.resolve_trust_ref(_valid_org(ci_trust_ref="env:ORGSEED_TRUST_ACME")) == "from-the-environment"


def test_resolve_trust_ref_fails_when_env_var_is_unset(monkeypatch):
    monkeypatch.delenv("ORGSEED_TRUST_ACME", raising=False)
    with pytest.raises(ValueError, match="ORGSEED_TRUST_ACME.*not set"):
        seed.resolve_trust_ref(_valid_org(ci_trust_ref="env:ORGSEED_TRUST_ACME"))


def test_resolve_trust_ref_fails_when_env_var_is_empty(monkeypatch):
    monkeypatch.setenv("ORGSEED_TRUST_ACME", "")
    with pytest.raises(ValueError, match="not set"):
        seed.resolve_trust_ref(_valid_org(ci_trust_ref="env:ORGSEED_TRUST_ACME"))


def test_resolve_trust_ref_refuses_the_shipped_placeholder():
    with pytest.raises(ValueError, match="placeholder"):
        seed.resolve_trust_ref(_valid_org(ci_trust_ref="CHANGE-ME-acme-commercial"))


def test_resolve_trust_ref_refuses_a_placeholder_supplied_via_env(monkeypatch):
    monkeypatch.setenv("ORGSEED_TRUST_ACME", "CHANGE-ME-acme-commercial")
    with pytest.raises(ValueError, match="placeholder"):
        seed.resolve_trust_ref(_valid_org(ci_trust_ref="env:ORGSEED_TRUST_ACME"))


def test_bootstrap_org_passes_the_resolved_external_id(monkeypatch, tmp_path):
    """The stack's CiTrustRef parameter must be the resolved secret, not the
    literal 'env:NAME' indirection string."""
    monkeypatch.setenv("ORGSEED_TRUST_ACME", "resolved-value")
    monkeypatch.setattr(seed, "OUTPUT_DIR", tmp_path)
    deployed = []
    monkeypatch.setattr(seed, "deploy_stack", lambda cfn, stack_name, template_path, params: deployed.append((stack_name, params)))
    session = MagicMock()

    org = _valid_org(ci_trust_ref="env:ORGSEED_TRUST_ACME")
    org["_hub_role_arn"] = "arn:aws:iam::111111111111:role/orgseed-hub"
    seed.bootstrap_org(session, "acme-commercial", org)

    roles_params = next(p for name, p in deployed if name.startswith("orgseed-roles-"))
    assert roles_params["CiTrustRef"] == "resolved-value"


# ---------------------------------------------------------------------------
# deploy_stack error handling
# ---------------------------------------------------------------------------

def test_deploy_stack_does_not_mistake_access_denied_for_a_missing_stack(tmp_path):
    """Previously ANY ClientError from describe_stacks meant 'create it', so an
    AccessDenied surfaced later as a confusing AlreadyExists."""
    cfn = _fake_cfn_client()
    cfn.describe_stacks.side_effect = FakeClientError("AccessDenied: not authorized to perform cloudformation:DescribeStacks")
    template = tmp_path / "t.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\n")

    with pytest.raises(FakeClientError, match="AccessDenied"):
        seed.deploy_stack(cfn, "orgseed-roles-acme", template, {})

    cfn.create_stack.assert_not_called()


@pytest.mark.parametrize("status", ["ROLLBACK_COMPLETE", "CREATE_FAILED", "DELETE_FAILED"])
def test_deploy_stack_explains_an_unupdatable_stack(tmp_path, status):
    cfn = _fake_cfn_client()
    cfn.describe_stacks.return_value = {"Stacks": [{"StackName": "orgseed-roles-acme", "StackStatus": status}]}
    template = tmp_path / "t.yaml"
    template.write_text("AWSTemplateFormatVersion: '2010-09-09'\n")

    with pytest.raises(RuntimeError, match=status):
        seed.deploy_stack(cfn, "orgseed-roles-acme", template, {})

    cfn.update_stack.assert_not_called()
    cfn.create_stack.assert_not_called()
