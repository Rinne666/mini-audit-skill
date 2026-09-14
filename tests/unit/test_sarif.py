"""Tests for runtime/sarif.py — SARIF normalization."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.sarif import (
    DEFAULT_RULE_CLASS_MAP,
    SarifError,
    assign_candidate_ids,
    dedupe_candidates,
    normalize_sarif,
    normalize_sarif_file,
)


def _sarif(results):
    return {
        "$schema": "https://example.com/sarif.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": [
                    {"id": "python.lang.security.audit.eval",
                     "shortDescription": {"text": "Use of eval"},
                     "defaultConfiguration": {"level": "error"}},
                ]}},
                "results": results,
            }
        ],
    }


def _sarif_with_rules(rules, results):
    return {
        "$schema": "https://example.com/sarif.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "semgrep", "rules": rules}},
                "results": results,
            }
        ],
    }


def test_normalize_simple_result() -> None:
    sarif = _sarif([
        {
            "ruleId": "python.lang.security.audit.eval",
            "message": {"text": "Use of eval is dangerous."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "app/main.py"},
                    "region": {"startLine": 42},
                }
            }],
            "level": "error",
        }
    ])
    out = normalize_sarif(sarif, source="semgrep")
    assert len(out) == 1
    c = out[0]
    assert c["source"] == "semgrep"
    assert c["rule_id"] == "python.lang.security.audit.eval"
    assert c["file"] == "app/main.py"
    assert c["line"] == 42
    assert c["class"] == "code_injection"
    assert c["confidence"] == "medium"
    assert c["status"] == "untriaged"
    assert c["candidate_id"].startswith("cand-semgrep-")


def test_normalize_unknown_rule_falls_back_to_uncategorized() -> None:
    sarif = _sarif([
        {"ruleId": "weird.new.rule.id", "message": {"text": "?"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"},
                                            "region": {"startLine": 1}}}]}
    ])
    out = normalize_sarif(sarif, source="semgrep")
    assert out[0]["class"] == "uncategorized"
    assert out[0]["confidence"] == "unknown"


def test_normalize_uses_longest_prefix() -> None:
    sarif = _sarif([
        {"ruleId": "python.lang.security.audit.subprocess-shell-true.var",
         "message": {"text": "x"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"},
                                            "region": {"startLine": 1}}}]}
    ])
    out = normalize_sarif(sarif, source="semgrep")
    assert out[0]["class"] == "command_injection"


def test_normalize_extracts_tags() -> None:
    sarif = _sarif_with_rules([
        {"id": "python.lang.security.audit.eval",
         "shortDescription": {"text": "eval"},
         "properties": {"tags": ["security", "CWE-95"]}},
    ], [
        {"ruleId": "python.lang.security.audit.eval", "message": {"text": "x"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"},
                                            "region": {"startLine": 1}}}]},
    ])
    out = normalize_sarif(sarif, source="semgrep")
    assert "security" in out[0]["tags"]


def test_normalize_invalid_input_raises() -> None:
    with pytest.raises(SarifError):
        normalize_sarif("not a dict")  # type: ignore[arg-type]


def test_normalize_file_roundtrip(tmp_path: Path) -> None:
    sarif = _sarif([
        {"ruleId": "python.lang.security.audit.eval", "message": {"text": "x"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"},
                                            "region": {"startLine": 1}}}]}
    ])
    p = tmp_path / "semgrep.sarif"
    p.write_text(json.dumps(sarif), encoding="utf-8")
    out = normalize_sarif_file(p, source="semgrep")
    assert len(out) == 1


def test_dedupe_candidates() -> None:
    sarif = _sarif([
        {"ruleId": "r1", "message": {"text": "x"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"},
                                            "region": {"startLine": 1}}}]},
        {"ruleId": "r1", "message": {"text": "x (dup)"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "x.py"},
                                            "region": {"startLine": 1}}}]},
    ])
    out = normalize_sarif(sarif, source="semgrep")
    deduped = dedupe_candidates(out)
    assert len(deduped) == 1


def test_assign_candidate_ids_handles_missing() -> None:
    raw = [{"file": "x.py", "line": 1, "message": "?"}]
    out = assign_candidate_ids(raw, source="manual")
    assert out[0]["candidate_id"].startswith("cand-manual-")
    assert out[0]["status"] == "untriaged"


def test_default_rule_class_map_is_not_empty() -> None:
    assert "python.lang.security.audit.eval" in DEFAULT_RULE_CLASS_MAP