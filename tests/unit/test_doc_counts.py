"""Hardening v1.1 §14 — doc/count contract drift.

`scripts/doc_counts.py` is the single source of truth for the numbers quoted
in SKILL.md / README.md / references/README.md. These tests pin the derivation
and the drift detection so a stale count fails CI rather than shipping.
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


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


doc_counts = _load("_doc_counts", SCRIPTS / "doc_counts.py")


@pytest.fixture(scope="module")
def metrics() -> dict:
    return doc_counts.collect_metrics(SKILL_ROOT)


def test_metrics_shape(metrics: dict) -> None:
    for key in (
        "reference_subdir_files", "reference_items", "inline_agents",
        "hunting_files", "vuln_class_files", "methodology_files",
        "wordlist_files", "eval_fixtures", "first_class_roles",
        "commands_total", "commands_full", "commands_partial",
        "commands_stub", "unit_tests", "runtime_version",
    ):
        assert key in metrics, key


def test_metrics_agree_with_manifest(metrics: dict) -> None:
    m = json.loads((SKILL_ROOT / "references" / "MANIFEST.json").read_text(encoding="utf-8"))
    assert metrics["reference_items"] == len(m["items"])
    assert metrics["reference_subdir_files"] == (
        metrics["hunting_files"] + metrics["vuln_class_files"]
        + metrics["methodology_files"] + metrics["wordlist_files"]
    )
    assert metrics["unit_tests"] > 0


def test_command_tally_sums_to_total(metrics: dict) -> None:
    assert metrics["commands_total"] == (
        metrics["commands_full"] + metrics["commands_partial"] + metrics["commands_stub"]
    )


def test_render_block_has_markers() -> None:
    block = doc_counts.render_block({"a": 1})
    assert block.startswith(doc_counts.BEGIN)
    assert block.rstrip().endswith(doc_counts.END)


def test_replace_block_is_idempotent() -> None:
    text = f"before\n{doc_counts.BEGIN}\nold\n{doc_counts.END}\nafter"
    block = doc_counts.render_block({"reference_items": 9})
    once = doc_counts.replace_block(text, block)
    assert once is not None
    assert "| manifest items (incl. inline agents) | 9 |" in once
    assert "before" in once and "after" in once
    assert doc_counts.replace_block(once, block) == once


def test_replace_block_without_markers_returns_none() -> None:
    assert doc_counts.replace_block("no markers here", "block") is None


def test_prose_claims_clean_on_repo(metrics: dict) -> None:
    assert doc_counts.prose_claims(SKILL_ROOT, metrics) == []


def test_prose_claims_detects_stale_skill_claim(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("nothing\n", encoding="utf-8")
    (tmp_path / "references").mkdir()
    (tmp_path / "references" / "README.md").write_text("nothing\n", encoding="utf-8")
    (tmp_path / "SKILL.md").write_text(
        "python -m pytest tests/unit -q        # 4 unit tests for runtime\n",
        encoding="utf-8",
    )
    problems = doc_counts.prose_claims(tmp_path, {"unit_tests": 999})
    assert any("unit test count" in p[1] and p[2] == 4 and p[3] == 999 for p in problems)


def test_prose_claims_detects_stale_role_claim(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("nothing\n", encoding="utf-8")
    (tmp_path / "SKILL.md").write_text("nothing\n", encoding="utf-8")
    (tmp_path / "references").mkdir()
    (tmp_path / "references" / "README.md").write_text(
        "- 6 first-class mavis agents\n", encoding="utf-8"
    )
    problems = doc_counts.prose_claims(tmp_path, {"first_class_roles": 7})
    assert any(p[1] == "first-class agent count" for p in problems)


def test_cli_check_passes_on_repo() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPTS / "doc_counts.py"), "--check",
         "--root", str(SKILL_ROOT)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "consistent" in result.stdout
