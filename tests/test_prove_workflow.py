"""
Structural tests for the prove workflow: the one that runs the least-privilege proof AS
the orgseed-ci role through the real OIDC -> hub -> orgseed-ci chain.

The whole value of that proof is WHO runs it. Run from an admin session it would prove
nothing, so the controls pinned here are about identity and containment.
"""
import pathlib
import re

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "prove.yml"
SHA_PIN = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


@pytest.fixture(scope="module")
def wf():
    return yaml.safe_load(WORKFLOW.read_text())


def steps(wf):
    return wf["jobs"]["least-privilege"]["steps"]


def test_only_a_manual_dispatch_starts_it(wf):
    triggers = wf[True] if True in wf else wf["on"]
    assert list(triggers) == ["workflow_dispatch"]


def test_it_runs_in_the_reviewed_environment(wf):
    """Same gate as everything else that reaches an org: a human approves first."""
    assert wf["jobs"]["least-privilege"]["environment"] == "orgseed"


def test_it_runs_as_the_ci_role_through_the_shared_session_action(wf):
    """The proof is only meaningful from the role's own session - the same chained
    session terraform.yml uses, never an admin role."""
    uses = [s for s in steps(wf) if s.get("uses") == "./.github/actions/orgseed-session"]
    assert len(uses) == 1
    assert uses[0]["with"]["hub-role-arn"] == "${{ secrets.ORGSEED_HUB_ROLE_ARN }}"


def test_it_never_reaches_for_the_admin_role_or_the_seed_path():
    text = WORKFLOW.read_text()
    assert "seed.py" not in text and "role-to-assume" not in text, "credentials come only from the session action"


def test_it_runs_the_negatives_script_against_the_rendered_backend(wf):
    run = " ".join(s.get("run", "") for s in steps(wf))
    assert "python cli/prove_ci_negatives.py" in run
    assert "--backend-hcl stacks/baseline/backend.hcl" in run


def test_a_failing_proof_fails_the_job(wf):
    """A proof that can't fail proves nothing. GitHub's DEFAULT shell for `run:` is
    `bash -e`, which has NO pipefail - so `python ... | tee` reports tee's success even
    when the script exits 1. The first real run printed RESULT: FAIL and went green. The step
    must opt into pipefail explicitly (`shell: bash` does; so does `set -o pipefail`)."""
    prove = next(s for s in steps(wf) if s.get("name", "").startswith("Prove"))
    assert "|| true" not in prove["run"]
    assert "tee" in prove["run"]
    assert prove.get("shell") == "bash" or "set -o pipefail" in prove["run"], "tee would swallow the script's exit status"


def test_the_summary_is_written_even_when_the_proof_fails(wf):
    summary = next(s for s in steps(wf) if s.get("name", "").startswith("Summarize"))
    assert summary["if"] == "always()"


def test_every_action_is_pinned_to_a_commit_sha(wf):
    for s in steps(wf):
        uses = s.get("uses")
        if uses and not uses.startswith("./"):
            assert SHA_PIN.match(uses), f"{uses} must be pinned to a full commit SHA"


def test_no_context_is_interpolated_into_a_shell_script(wf):
    for s in steps(wf):
        if "run" in s:
            assert "${{" not in s["run"], "pass values through env, never into script text"


def test_the_evidence_artifact_is_short_lived(wf):
    upload = next(s for s in steps(wf) if s.get("uses", "").startswith("actions/upload-artifact"))
    assert upload["with"]["retention-days"] <= 7
    assert upload["with"]["path"].endswith("ci-negatives.json"), "only the identifier-free evidence file"
