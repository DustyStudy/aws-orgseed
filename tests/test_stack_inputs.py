"""
Tests for cli/stack_inputs.py: renders the Phase 1 stack's backend.hcl and
terraform.tfvars.json from the (masked, secret) org config, and emits ::add-mask::
lines so the identifiers can't reach a public log.
"""
import json

import pytest
import yaml

import seed
import stack_inputs


def _config(**org_overrides):
    org = {
        "alias": "sandbox",
        "management_account_id": "222222222222",
        "partition": "aws",
        "regions": ["us-east-1"],
        "seeding_admin_role_name": "OrgSeedAdmin",
        "ci_role_name": "orgseed-ci",
        "state_bucket": "tfstate-sandbox-222222222222",
        "ci_trust_ref": "env:ORGSEED_TRUST_SANDBOX",
        "baseline": {"scp_target_id": "ou-abcd-12345678"},
    }
    org.update(org_overrides)
    return {
        "hub_account_id": "111111111111",
        "hub_role_arn": "arn:aws:iam::111111111111:role/orgseed-hub",
        "github_repo": "DustyStudy/aws-orgseed",
        "orgs": [org],
    }


@pytest.fixture
def cfg_file(tmp_path):
    def make(**org_overrides):
        p = tmp_path / "orgs.yaml"
        p.write_text(yaml.safe_dump(_config(**org_overrides)))
        return p
    return make


def run(cfg_path, tmp_path, monkeypatch, capsys, alias="sandbox"):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    gh_out = tmp_path / "gh_output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(gh_out))
    stack_inputs.main(["--config", str(cfg_path), "--org", alias, "--stack-dir", str(out)])
    return out, capsys.readouterr().out, gh_out.read_text() if gh_out.exists() else ""


def test_backend_hcl_points_at_the_orgs_state_bucket(cfg_file, tmp_path, monkeypatch, capsys):
    out, _, _ = run(cfg_file(), tmp_path, monkeypatch, capsys)
    hcl = (out / "backend.hcl").read_text()
    assert 'bucket       = "tfstate-sandbox-222222222222"' in hcl
    assert 'region       = "us-east-1"' in hcl
    assert "use_lockfile = true" in hcl and "encrypt      = true" in hcl
    assert "dynamodb_table" not in hcl


def test_backend_key_matches_the_one_seed_py_writes(cfg_file, tmp_path, monkeypatch, capsys):
    """If these drift, Terraform silently starts a brand-new empty state."""
    out, _, _ = run(cfg_file(), tmp_path, monkeypatch, capsys)
    key_line = next(line for line in (out / "backend.hcl").read_text().splitlines() if line.strip().startswith("key"))
    seed_dir = tmp_path / "seed_out"
    seed.OUTPUT_DIR = seed_dir
    seed.write_backend_tf("sandbox", _config()["orgs"][0])
    seed_key = next(line for line in (seed_dir / "sandbox" / "backend.tf").read_text().splitlines() if line.strip().startswith("key"))
    assert key_line.split("=", 1)[1].strip() == seed_key.split("=", 1)[1].strip()


def test_dynamodb_lock_table_when_configured(cfg_file, tmp_path, monkeypatch, capsys):
    out, _, _ = run(cfg_file(use_lock_table=True, lock_table="tflock-sandbox"), tmp_path, monkeypatch, capsys)
    hcl = (out / "backend.hcl").read_text()
    assert 'dynamodb_table = "tflock-sandbox"' in hcl and "use_lockfile" not in hcl


def test_tfvars_carry_the_stack_inputs(cfg_file, tmp_path, monkeypatch, capsys):
    out, _, _ = run(cfg_file(), tmp_path, monkeypatch, capsys)
    tfvars = json.loads((out / "terraform.tfvars.json").read_text())
    assert tfvars == {
        "org_alias": "sandbox",
        "partition": "aws",
        "ci_role_name": "orgseed-ci",
        "scp_target_id": "ou-abcd-12345678",
    }


def test_optional_baseline_settings_pass_through(cfg_file, tmp_path, monkeypatch, capsys):
    out, _, _ = run(cfg_file(baseline={"scp_target_id": "ou-abcd-12345678", "enforce_imdsv2": False}), tmp_path, monkeypatch, capsys)
    assert json.loads((out / "terraform.tfvars.json").read_text())["enforce_imdsv2"] is False


def test_identifiers_are_masked_before_anything_else_prints_them(cfg_file, tmp_path, monkeypatch, capsys):
    _, stdout, _ = run(cfg_file(), tmp_path, monkeypatch, capsys)
    masked = {line.split("::add-mask::", 1)[1] for line in stdout.splitlines() if line.startswith("::add-mask::")}
    assert {"222222222222", "111111111111", "tfstate-sandbox-222222222222", "ou-abcd-12345678"} <= masked


def test_ci_role_arn_output_follows_the_partition(cfg_file, tmp_path, monkeypatch, capsys):
    _, _, gh = run(cfg_file(), tmp_path, monkeypatch, capsys)
    assert "ci_role_arn=arn:aws:iam::222222222222:role/orgseed-ci" in gh
    _, _, gh = run(cfg_file(partition="aws-us-gov"), tmp_path, monkeypatch, capsys)
    assert "ci_role_arn=arn:aws-us-gov:iam::222222222222:role/orgseed-ci" in gh


def test_region_output_is_the_orgs_first_region(cfg_file, tmp_path, monkeypatch, capsys):
    _, _, gh = run(cfg_file(regions=["eu-west-1", "us-east-1"]), tmp_path, monkeypatch, capsys)
    assert "region=eu-west-1" in gh


def test_unknown_org_is_refused(cfg_file, tmp_path, monkeypatch, capsys):
    with pytest.raises(SystemExit, match="Unknown org alias"):
        run(cfg_file(), tmp_path, monkeypatch, capsys, alias="nope")


def test_org_without_a_baseline_block_is_refused(cfg_file, tmp_path, monkeypatch, capsys):
    cfg = _config()
    del cfg["orgs"][0]["baseline"]
    p = tmp_path / "orgs.yaml"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.raises(SystemExit, match="baseline"):
        run(p, tmp_path, monkeypatch, capsys)


@pytest.mark.parametrize("bad", ["r-abcd", "123456789012", "ou-x", ""])
def test_a_target_that_is_not_an_ou_is_refused_before_terraform_runs(cfg_file, tmp_path, monkeypatch, capsys, bad):
    """Same guard as the stack's own validation, but failing in seconds with a
    readable message instead of after the role chain and terraform init."""
    with pytest.raises(SystemExit, match="OU"):
        run(cfg_file(baseline={"scp_target_id": bad}), tmp_path, monkeypatch, capsys)
