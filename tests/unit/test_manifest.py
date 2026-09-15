"""Hardening v1.1 §13 — reference provenance + manifest integrity.

Covers `scripts/manifest.py` (generator) and `scripts/check-manifest.py`
(verifier). The key regression guard: the manifest must carry real
provenance (source repo/commit/path, license, modified, imported_at) for
every item, and the checker must fail when provenance or declared counts
drift from disk.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SKILL_ROOT = Path(__file__).resolve().parent.parent.parent
SCRIPTS = SKILL_ROOT / "scripts"
REFS = SKILL_ROOT / "references"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


manifest_gen = _load("_manifest_gen", SCRIPTS / "manifest.py")
check_manifest = _load("_check_manifest", SCRIPTS / "check-manifest.py")


# ---------------------------------------------------------------------------
# rule matching
# ---------------------------------------------------------------------------


def test_match_is_component_wise() -> None:
    """`*.md` must match only top-level files, not nested ones."""
    assert manifest_gen._match("*.md", "advisory-hunter.md") is True
    assert manifest_gen._match("*.md", "hunting/hunt-xss.md") is False
    assert manifest_gen._match("hunting/*.md", "hunting/hunt-xss.md") is True
    assert manifest_gen._match("hunting/*.md", "advisory-hunter.md") is False
    assert manifest_gen._match("methodology/*.md", "methodology/bug-bounty.md") is True


# ---------------------------------------------------------------------------
# provenance resolution
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def prov() -> dict:
    return json.loads((REFS / "PROVENANCE.json").read_text(encoding="utf-8"))


def test_resolve_hunting(prov: dict) -> None:
    out = manifest_gen.resolve_provenance("hunting/hunt-xss.md", prov)
    assert out["source_repo"] == "claude-bughunter"
    assert out["source_path"] == "skills/hunt-xss/SKILL.md"
    assert out["modified"] is False


def test_resolve_vuln_class(prov: dict) -> None:
    out = manifest_gen.resolve_provenance("vuln-classes/xss.md", prov)
    assert out["source_repo"] == "strix"
    assert out["source_path"] == "skills/vulnerabilities/xss.md"


def test_resolve_inline_agent_is_modified_piolium(prov: dict) -> None:
    out = manifest_gen.resolve_provenance("advisory-hunter.md", prov)
    assert out["source_repo"] == "piolium"
    assert out["source_path"] == "agents/advisory-hunter.md"
    assert out["modified"] is True  # frontmatter + codex-trim stripped


def test_resolve_methodology_override(prov: dict) -> None:
    """permission-delta-judging.md is an original, not a Claude-BugHunter copy."""
    out = manifest_gen.resolve_provenance(
        "methodology/permission-delta-judging.md", prov
    )
    assert out["source_repo"] == "local"
    assert out["modified"] is False
    assert "note" in out


def test_resolve_local_readme(prov: dict) -> None:
    out = manifest_gen.resolve_provenance("README.md", prov)
    assert out["source_repo"] == "local"


def test_resolve_commit_prefers_map_then_source(prov: dict) -> None:
    mapped = manifest_gen.resolve_commit("advisory-hunter.md", "piolium", prov)
    assert len(mapped) == 40 and mapped != "UNKNOWN"
    # claude-bughunter has no local checkout -> declared default
    unmapped = manifest_gen.resolve_commit(
        "hunting/hunt-xss.md", "claude-bughunter", prov
    )
    assert unmapped == "UNKNOWN"


# ---------------------------------------------------------------------------
# manifest generation over the real tree
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def built() -> dict:
    return manifest_gen.build_manifest(REFS)


def test_built_manifest_has_uniform_provenance(built: dict) -> None:
    assert built["schema_version"] == 2
    assert built["item_count"] == len(built["items"]) > 0
    required = set(check_manifest.REQUIRED_PROVENANCE)
    for item in built["items"]:
        missing = required - set(item)
        assert not missing, f"{item['path']} missing {missing}"
        assert item["source_repo"] in built["sources"]
        assert item["license"] == built["sources"][item["source_repo"]]["license"]


def test_built_manifest_commits_resolved_for_piolium(built: dict) -> None:
    piolium = [i for i in built["items"] if i["source_repo"] == "piolium"]
    assert len(piolium) == 28
    assert all(len(i["source_commit"]) == 40 for i in piolium)
    assert all(i["license"] == "MIT" for i in piolium)


def test_built_manifest_matches_committed_manifest(built: dict) -> None:
    """Regeneration must be deterministic — committed file == computed file."""
    on_disk = json.loads((REFS / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest_gen._stable(on_disk) == manifest_gen._stable(built)


# ---------------------------------------------------------------------------
# checker CLI
# ---------------------------------------------------------------------------


def _run_check(root: Path, *extra: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPTS / "check-manifest.py"),
         "--root", str(root), *extra],
        capture_output=True, text=True, check=False,
    )


def test_check_manifest_passes_on_repo() -> None:
    result = _run_check(REFS, "--strict")
    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    assert summary["errors"] == 0
    assert summary["manifest_schema_version"] == 2


def _mini_tree(tmp_path: Path) -> Path:
    """A tiny references tree with one file per category + local provenance."""
    root = tmp_path / "references"
    (root / "hunting").mkdir(parents=True)
    (root / "vuln-classes").mkdir(parents=True)
    (root / "hunting" / "hunt-a.md").write_text("a\n", encoding="utf-8")
    (root / "vuln-classes" / "c.md").write_text("c\n", encoding="utf-8")
    (root / "agent.md").write_text("g\n", encoding="utf-8")
    (root / "README.md").write_text("x\n", encoding="utf-8")
    (root / "PROVENANCE.json").write_text(
        json.dumps({
            "schema_version": 1, "kind": "reference-provenance",
            "imported_at": "2026-09-15",
            "sources": {"local": {"repo": "local", "license": "MIT",
                                  "commit": "local"}},
            "modified_by_source": {"local": False},
            "rules": [{"match": "*", "source": "local", "source_path": "{rel}"}],
            "commit_map": {},
        }), encoding="utf-8",
    )
    return root


def test_check_manifest_detects_missing_provenance(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path)
    manifest_gen.build_manifest  # ensure import path resolved
    m = manifest_gen.build_manifest(root)
    # strip provenance from one item -> must be an error
    for item in m["items"]:
        if item["path"] == "agent.md":
            for k in check_manifest.REQUIRED_PROVENANCE:
                item.pop(k)
    (root / "MANIFEST.json").write_text(
        manifest_gen._stable(m) + "\n", encoding="utf-8"
    )
    result = _run_check(root, "--strict")
    assert result.returncode == 1
    assert "provenance missing" in result.stderr


def test_check_manifest_detects_count_drift(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path)
    # README claims 2 hunting files but only 1 exists
    (root / "README.md").write_text(
        "├── hunting/   ← 2 files\n", encoding="utf-8"
    )
    m = manifest_gen.build_manifest(root)
    (root / "MANIFEST.json").write_text(
        manifest_gen._stable(m) + "\n", encoding="utf-8"
    )
    result = _run_check(root, "--strict")
    assert result.returncode == 1
    assert "hunting" in result.stderr and "on-disk" in result.stderr


def test_manifest_check_mode_detects_drift(tmp_path: Path) -> None:
    root = _mini_tree(tmp_path)
    m = manifest_gen.build_manifest(root)
    (root / "MANIFEST.json").write_text(
        manifest_gen._stable(m) + "\n", encoding="utf-8"
    )
    ok = subprocess.run(
        [sys.executable, str(SCRIPTS / "manifest.py"), "--root", str(root), "--check"],
        capture_output=True, text=True, check=False,
    )
    assert ok.returncode == 0, ok.stderr
    # mutate a file -> generator check must notice
    (root / "agent.md").write_text("changed\n", encoding="utf-8")
    drift = subprocess.run(
        [sys.executable, str(SCRIPTS / "manifest.py"), "--root", str(root), "--check"],
        capture_output=True, text=True, check=False,
    )
    assert drift.returncode == 1
    assert "drift" in drift.stderr
