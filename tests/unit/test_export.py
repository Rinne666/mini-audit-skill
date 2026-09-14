"""Tests for runtime/export.py — JSON / Markdown / SARIF exporters."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.export import (
    Exporter,
    export_json,
    export_markdown,
    export_sarif,
)
from runtime.findings import FindingStore
from runtime.fingerprint import compute_fingerprint


def _confirmed(**overrides):
    base = {
        "id": "F-001",
        "verdict": "confirmed",
        "class": "idor",
        "title": "IDOR on invoice lookup",
        "summary": "An authenticated ordinary user can read other tenants' invoices.",
        "source_ref": {"commit": "abc123", "tree_hash": "t"},
        "attacker": {"identity": "authenticated ordinary user", "existing_authority": "read own tenant invoices"},
        "boundary": {
            "type": "tenant_isolation",
            "security_invariant": "Tenant A cannot access Tenant B objects",
            "before_capability": "read Tenant A invoices",
            "after_capability": "read Tenant B invoices",
            "crossed": True,
        },
        "root_cause": "Missing ownership check before findById",
        "trace": [
            {"kind": "entrypoint", "file": "src/api.ts", "line": 40, "symbol": "getInvoice"},
            {"kind": "sink", "file": "src/db.ts", "line": 60, "symbol": "findById"},
        ],
        "severity": {"overall": "high"},
        "verification": {"technical_verifier": "verify-c001"},
    }
    base.update(overrides)
    base["fingerprint"] = compute_fingerprint(base)
    return base


def _rejected(**overrides):
    base = {
        "id": "F-002",
        "verdict": "rejected",
        "disposition_reason": "equivalent_capability",
        "class": "rce",
        "title": "Admin shell",
        "summary": "Admin already has scripting capability; by design.",
        "source_ref": {"commit": "abc", "tree_hash": "t"},
        "trace": [{"kind": "sink", "file": "x.py", "line": 1, "symbol": "exec"}],
    }
    base.update(overrides)
    base["fingerprint"] = compute_fingerprint(base)
    return base


def _store() -> FindingStore:
    s = FindingStore.empty(audit_id="audit-x")
    s.upsert(_confirmed())
    # second confirmed finding differs in class & boundary to produce a distinct fingerprint
    ssrf_overrides = dict(
        id="F-002",
        boundary={
            "type": "network_egress",
            "security_invariant": "Server cannot be tricked into making outbound requests to attacker-controlled hosts",
            "before_capability": "fetch public CDN only",
            "after_capability": "fetch internal metadata endpoint",
            "crossed": True,
        },
        root_cause="User-controlled URL passed to HTTP client without allowlist",
        trace=[
            {"kind": "entrypoint", "file": "src/webhook.py", "line": 12, "symbol": "register_webhook"},
            {"kind": "sink", "file": "src/http.py", "line": 90, "symbol": "fetch"},
        ],
        severity={"overall": "critical"},
    )
    ssrf_overrides["class"] = "ssrf"
    s.upsert(_confirmed(**ssrf_overrides))
    s.upsert(_rejected(id="F-003"))
    return s


def test_export_json_writes_filtered_set(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    n = export_json(_store(), path=out, verdict="confirmed")
    assert n == 2
    data = json.loads(out.read_text(encoding="utf-8"))
    assert all(f["verdict"] == "confirmed" for f in data["findings"])
    assert data["stats"]["confirmed"] == 2


def test_export_json_min_severity_filter(tmp_path: Path) -> None:
    out = tmp_path / "out.json"
    n = export_json(_store(), path=out, min_severity="critical")
    assert n == 1
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["findings"][0]["severity"]["overall"] == "critical"


def test_export_markdown_contains_severity_badge(tmp_path: Path) -> None:
    out = tmp_path / "out.md"
    export_markdown(_store(), path=out)
    text = out.read_text(encoding="utf-8")
    # Both F-001 (high) and F-002 (critical) should be present
    assert "🟠 HIGH" in text
    assert "🔴 CRITICAL" in text
    assert "mini-audit report" in text


def test_export_markdown_handles_empty(tmp_path: Path) -> None:
    empty = FindingStore.empty(audit_id="x")
    out = tmp_path / "out.md"
    export_markdown(empty, path=out)
    assert "No findings" in out.read_text(encoding="utf-8")


def test_export_sarif_basic(tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    n = export_sarif(_store(), path=out, verdict="confirmed")
    assert n == 2
    sarif = json.loads(out.read_text(encoding="utf-8"))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "mini-audit"
    assert len(sarif["runs"][0]["results"]) == 2
    # Each result has fingerprint property
    for r in sarif["runs"][0]["results"]:
        assert "fingerprint" in r["properties"]


def test_export_sarif_uses_locations_from_trace(tmp_path: Path) -> None:
    out = tmp_path / "out.sarif"
    export_sarif(_store(), path=out, verdict="confirmed")
    sarif = json.loads(out.read_text(encoding="utf-8"))
    results = sarif["runs"][0]["results"]
    assert any(
        r.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri") == "src/api.ts"
        for r in results
    )


def test_exporter_class_dispatch(tmp_path: Path) -> None:
    e = Exporter(_store())
    n1 = e.export(fmt="json", path=tmp_path / "a.json")
    n2 = e.export(fmt="md", path=tmp_path / "a.md")
    n3 = e.export(fmt="sarif", path=tmp_path / "a.sarif")
    assert n1 == 3 and n2 == 3 and n3 == 3


def test_exporter_unknown_format_raises(tmp_path: Path) -> None:
    e = Exporter(_store())
    with pytest.raises(ValueError):
        e.export(fmt="xml", path=tmp_path / "x.xml")