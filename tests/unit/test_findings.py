"""Tests for runtime/findings.py — canonical finding store."""
from __future__ import annotations

from pathlib import Path

import pytest

from runtime.findings import (
    VERDICT_CONFIRMED,
    VERDICT_NEEDS_VALIDATION,
    VERDICT_REJECTED,
    FindingStore,
    FindingValidationError,
    validate_finding,
)
from runtime.fingerprint import compute_fingerprint


def _confirmed(**overrides):
    base = {
        "id": "F-001",
        "verdict": VERDICT_CONFIRMED,
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
        "verdict": VERDICT_REJECTED,
        "disposition_reason": "equivalent_capability",
        "class": "rce",
        "title": "Admin can run shell",
        "summary": "Admin already has scripting capability; this is by design.",
        "source_ref": {"commit": "abc", "tree_hash": "t"},
        "trace": [{"kind": "sink", "file": "x.py", "line": 1, "symbol": "exec"}],
    }
    base.update(overrides)
    base["fingerprint"] = compute_fingerprint(base)
    return base


def test_validate_confirmed_finding_ok() -> None:
    validate_finding(_confirmed())


def test_validate_rejected_finding_ok() -> None:
    validate_finding(_rejected())


def test_validate_rejected_requires_disposition_reason() -> None:
    f = _rejected()
    f.pop("disposition_reason")
    f["fingerprint"] = compute_fingerprint(f)
    with pytest.raises(FindingValidationError):
        validate_finding(f)


def test_validate_rejects_invalid_disposition_reason() -> None:
    f = _rejected(disposition_reason="nonsense")
    f["fingerprint"] = compute_fingerprint(f)
    with pytest.raises(FindingValidationError):
        validate_finding(f)


def test_validate_confirmed_requires_severity_overall() -> None:
    f = _confirmed()
    f["severity"] = {}
    f["fingerprint"] = compute_fingerprint(f)
    with pytest.raises(FindingValidationError):
        validate_finding(f)


def test_validate_confirmed_requires_boundary_crossed_true() -> None:
    f = _confirmed()
    f["boundary"]["crossed"] = False
    f["fingerprint"] = compute_fingerprint(f)
    with pytest.raises(FindingValidationError):
        validate_finding(f)


def test_validate_rejects_fingerprint_mismatch() -> None:
    f = _confirmed()
    f["fingerprint"] = "v1:" + "0" * 64
    with pytest.raises(FindingValidationError):
        validate_finding(f)


def test_validate_rejects_empty_trace() -> None:
    f = _confirmed(trace=[])
    f["fingerprint"] = compute_fingerprint(f)
    with pytest.raises(FindingValidationError):
        validate_finding(f)


def test_validate_rejects_missing_source_ref_commit() -> None:
    f = _confirmed(source_ref={"tree_hash": "x"})
    f["fingerprint"] = compute_fingerprint(f)
    with pytest.raises(FindingValidationError):
        validate_finding(f)


def test_store_upsert_dedupes_by_fingerprint(tmp_path: Path) -> None:
    store = FindingStore.empty(audit_id="test")
    f1 = _confirmed()
    store.upsert(f1)
    f2 = _confirmed(id="F-999")  # same content
    store.upsert(f2)
    assert len(store.findings) == 1


def test_store_upsert_merges_trace(tmp_path: Path) -> None:
    store = FindingStore.empty(audit_id="test")
    f1 = _confirmed(trace=[
        {"kind": "entrypoint", "file": "a.py", "line": 1, "symbol": "foo"},
    ])
    store.upsert(f1)
    f2 = _confirmed(trace=[
        {"kind": "sink", "file": "b.py", "line": 2, "symbol": "bar"},
        {"kind": "entrypoint", "file": "a.py", "line": 1, "symbol": "foo"},  # dup
    ])
    merged = store.upsert(f2)
    assert len(merged["trace"]) == 2


def test_store_filter_by_verdict_and_severity(tmp_path: Path) -> None:
    store = FindingStore.empty(audit_id="test")
    store.upsert(_confirmed(severity={"overall": "high"}))
    ssrf_overrides = dict(
        id="F-002",
        boundary={
            "type": "network_egress",
            "security_invariant": "Server cannot reach attacker hosts",
            "before_capability": "fetch public CDN",
            "after_capability": "fetch internal metadata",
            "crossed": True,
        },
        root_cause="no allowlist",
        trace=[
            {"kind": "entrypoint", "file": "src/wh.py", "line": 12, "symbol": "register"},
            {"kind": "sink", "file": "src/h.py", "line": 90, "symbol": "fetch"},
        ],
        severity={"overall": "critical"},
    )
    ssrf_overrides["class"] = "ssrf"
    store.upsert(_confirmed(**ssrf_overrides))
    store.upsert(_rejected(id="F-003"))

    confirmed = store.filter(verdict="confirmed")
    assert len(confirmed) == 2
    high_plus = store.filter(verdict="confirmed", min_severity="high")
    assert len(high_plus) == 2
    crit = store.filter(min_severity="critical")
    assert len(crit) == 1


def test_store_save_load_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    store = FindingStore.empty(audit_id="audit-1")
    store.upsert(_confirmed())
    store.save(path)
    loaded = FindingStore.load(path)
    assert loaded.audit_id == "audit-1"
    assert len(loaded.findings) == 1
    assert loaded.findings[0]["verdict"] == VERDICT_CONFIRMED


def test_store_stats() -> None:
    store = FindingStore.empty(audit_id="t")
    store.upsert(_confirmed(severity={"overall": "high"}))
    ssrf_overrides = dict(
        id="F-002",
        boundary={
            "type": "network_egress",
            "security_invariant": "Server cannot reach attacker hosts",
            "before_capability": "fetch public CDN",
            "after_capability": "fetch internal metadata",
            "crossed": True,
        },
        root_cause="no allowlist",
        trace=[
            {"kind": "entrypoint", "file": "src/wh.py", "line": 12, "symbol": "register"},
            {"kind": "sink", "file": "src/h.py", "line": 90, "symbol": "fetch"},
        ],
        severity={"overall": "critical"},
    )
    ssrf_overrides["class"] = "ssrf"
    store.upsert(_confirmed(**ssrf_overrides))
    store.upsert(_rejected(id="F-003"))
    needs = {"id": "F-004", "verdict": VERDICT_NEEDS_VALIDATION, "class": "race",
             "title": "race on counter", "summary": "race maybe",
             "source_ref": {"commit": "x", "tree_hash": "y"},
             "trace": [{"kind": "sink", "file": "x.py", "line": 1, "symbol": "increment"}]}
    needs["fingerprint"] = compute_fingerprint(needs)
    store.upsert(needs)
    stats = store.stats()
    assert stats["total"] == 4
    assert stats["confirmed"] == 2
    assert stats["needs_validation"] == 1
    assert stats["rejected"] == 1
    assert stats["severity_high"] == 1
    assert stats["severity_critical"] == 1