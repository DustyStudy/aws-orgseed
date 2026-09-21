"""
Structural tests for the Phase 1 terraform workflow and its composite session
action. Each pins a control, not a style point: together they are why a run of
this workflow can be trusted with an organization's guardrails.
"""
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "terraform.yml"
ACTION = ROOT / ".github" / "actions" / "orgseed-session" / "action.yml"
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


@pytest.fixture(scope="module")
def wf():
    return yaml.safe_load(WORKFLOW.read_text())


@pytest.fixture(scope="module")
def action():
    return yaml.safe_load(ACTION.read_text())


def all_steps(wf):
    for job in wf["jobs"].values():
        yield from job["steps"]


def test_only_a_manual_dispatch_can_start_it(wf):
    triggers = wf[True] if True in wf else wf["on"]  # PyYAML parses a bare `on` key as boolean True
    assert list(triggers) == ["workflow_dispatch"]


def test_action_is_a_closed_choice_defaulting_to_the_read_only_one(wf):
    inp = (wf[True] if True in wf else wf["on"])["workflow_dispatch"]["inputs"]["action"]
    assert inp["type"] == "choice" and inp["default"] == "plan"
    assert inp["options"] == ["plan", "apply", "destroy"]


def test_every_job_that_touches_the_org_is_gated_by_the_orgseed_environment(wf):
    """The hub trusts only environment:orgseed, and that environment requires a
    reviewer - so BOTH the plan and the apply pause for a human."""
    for name, job in wf["jobs"].items():
        assert job["environment"] == "orgseed", f"job '{name}' must run in the orgseed environment"


def test_apply_only_runs_after_a_plan_and_never_for_a_plain_plan(wf):
    apply_job = wf["jobs"]["apply"]
    assert apply_job["needs"] == "plan"
    assert "inputs.action != 'plan'" in apply_job["if"]


def test_apply_applies_the_reviewed_plan_file_never_auto_approves(wf):
    """`terraform apply <planfile>` applies exactly what was reviewed and refuses
    if state changed since; -auto-approve would re-plan and apply whatever it finds."""
    runs = " ".join(s.get("run", "") for s in wf["jobs"]["apply"]["steps"])
    assert "terraform -chdir=stacks/baseline apply -input=false tfplan" in runs
    assert "-auto-approve" not in runs


def test_the_plan_artifact_is_encrypted_and_short_lived(wf):
    """Artifacts on a public repo are downloadable by any signed-in GitHub user, and
    a plan embeds the OU ID and org data."""
    plan_job = wf["jobs"]["plan"]["steps"]
    run = " ".join(s.get("run", "") for s in plan_job)
    assert "openssl enc -aes-256-cbc -pbkdf2" in run and "-pass env:PLAN_KEY" in run
    upload = next(s for s in plan_job if s.get("uses", "").startswith("actions/upload-artifact"))
    assert upload["with"]["path"] == "tfplan.enc", "only the encrypted file may be uploaded"
    assert upload["with"]["retention-days"] <= 1
    apply_run = " ".join(s.get("run", "") for s in wf["jobs"]["apply"]["steps"])
    assert "openssl enc -d -aes-256-cbc -pbkdf2" in apply_run


def test_plan_key_comes_from_a_secret(wf):
    for job in ("plan", "apply"):
        env = " ".join(str(s.get("env", {})) for s in wf["jobs"][job]["steps"])
        assert "secrets.ORGSEED_PLAN_KEY" in env


def test_the_job_summary_lists_changes_but_never_attribute_values(wf):
    """Summaries are not reliably masked; addresses and counts carry no IDs."""
    run = " ".join(s.get("run", "") for s in wf["jobs"]["plan"]["steps"])
    assert "GITHUB_STEP_SUMMARY" in run
    assert "show -no-color tfplan" in run and "grep -E" in run, "summary must be filtered to the plan's headline lines"


def test_every_action_is_pinned_to_a_commit_sha(wf, action):
    steps = list(all_steps(wf)) + action["runs"]["steps"]
    for s in steps:
        uses = s.get("uses")
        if uses and not uses.startswith("./"):
            assert SHA_PIN.match(uses), f"{uses} must be pinned to a full commit SHA"


def test_no_context_is_interpolated_into_a_shell_script(wf, action):
    """secrets.* / inputs.* / github.event.* inside `run:` text is injection. Values
    reach scripts through env: only."""
    scripts = [s["run"] for s in all_steps(wf) if "run" in s] + [s["run"] for s in action["runs"]["steps"] if "run" in s]
    for script in scripts:
        assert "${{" not in script, "no ${{ }} expressions inside run: scripts - pass via env"


def test_session_action_chains_hub_into_the_ci_role_with_the_external_id(action):
    steps = action["runs"]["steps"]
    creds = [s for s in steps if s.get("uses", "").startswith("aws-actions/configure-aws-credentials")]
    assert len(creds) == 2, "one OIDC step (hub), one chained step (orgseed-ci)"
    chained = creds[1]["with"]
    assert chained["role-chaining"] is True
    assert chained["role-external-id"] == "${{ inputs.external-id }}"
    assert chained["role-to-assume"] == "${{ steps.render.outputs.ci_role_arn }}"


def test_session_action_masks_identifiers_before_assuming_anything(action):
    steps = action["runs"]["steps"]
    names = [s.get("id") or s.get("name") for s in steps]
    assert names.index("render") < next(i for i, s in enumerate(steps) if s.get("uses", "").startswith("aws-actions/configure-aws-credentials"))


def test_the_workflow_never_uses_the_sessions_role_for_the_seed_stacks(wf):
    """orgseed-ci is for guardrails. The bootstrap stacks stay with OrgSeedAdmin/seed.yml."""
    text = WORKFLOW.read_text()
    assert "OrgSeedAdmin" not in text and "seed.py" not in text
