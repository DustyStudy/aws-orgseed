"""
Repo-hygiene checks that keep dependency automation and reproducibility honest.

These are the kind of thing that fails SILENTLY: a Dependabot entry that points at a
directory with no .tf files simply never runs, and an ignored lock file means every plan can
pick up a different provider release.
"""
import fnmatch
import pathlib

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent


def terraform_dirs():
    found = set()
    for base in ("modules", "stacks"):
        for tf in (ROOT / base).rglob("*.tf"):
            rel = tf.relative_to(ROOT)
            if ".terraform" in rel.parts or "tests" in rel.parts:
                continue
            found.add("/" + tf.parent.relative_to(ROOT).as_posix())
    return found


def test_dependabot_watches_every_directory_that_contains_terraform():
    cfg = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text())
    entry = next(u for u in cfg["updates"] if u["package-ecosystem"] == "terraform")
    patterns = entry.get("directories") or [entry["directory"]]
    unwatched = [d for d in sorted(terraform_dirs()) if not any(fnmatch.fnmatch(d, p) for p in patterns)]
    assert not unwatched, f"Dependabot never looks at: {unwatched}"


def test_the_stacks_provider_lock_file_is_committed_with_linux_hashes():
    """CI runs on linux_amd64. Without a committed lock, plan and apply can silently use
    different provider releases."""
    lock = ROOT / "stacks" / "baseline" / ".terraform.lock.hcl"
    assert lock.exists(), "commit the lock file (and allow it in .gitignore)"
    text = lock.read_text()
    assert 'provider "registry.terraform.io/hashicorp/aws"' in text
    assert "h1:" in text and "zh:" in text
