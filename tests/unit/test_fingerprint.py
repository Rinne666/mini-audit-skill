"""Tests for runtime/fingerprint.py — stable finding fingerprints."""
from __future__ import annotations

import pytest

from runtime.fingerprint import (
    FINGERPRINT_VERSION,
    FindingFingerprint,
    compute_fingerprint,
    dedupe_findings,
)


def _minimal_finding(**overrides):
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
            {"kind": "propagation", "file": "src/service.ts", "line": 91, "symbol": "lookupInvoice"},
            {"kind": "sink", "file": "src/db.ts", "line": 60, "symbol": "findById"},
        ],
        "severity": {"overall": "high"},
        "verification": {"technical_verifier": "verify-c001"},
    }
    base.update(overrides)
    return base


def test_fingerprint_versioned_and_deterministic() -> None:
    f1 = _minimal_finding()
    fp1 = compute_fingerprint(f1)
    assert fp1.startswith(f"{FINGERPRINT_VERSION}:")
    assert len(fp1.split(":", 1)[1]) == 64

    f2 = _minimal_finding()
    fp2 = compute_fingerprint(f2)
    assert fp1 == fp2


def test_fingerprint_insensitive_to_line_numbers() -> None:
    f1 = _minimal_finding()
    f2 = _minimal_finding()
    # Mutate line numbers; fingerprint must remain identical
    for step in f2["trace"]:
        step["line"] = step["line"] + 1000
    assert compute_fingerprint(f1) == compute_fingerprint(f2)


def test_fingerprint_insensitive_to_finding_id_and_severity() -> None:
    f1 = _minimal_finding()
    f2 = _minimal_finding(id="F-999", title="different title", summary="different summary text", )
    f2["severity"]["overall"] = "critical"
    assert compute_fingerprint(f1) == compute_fingerprint(f2)


def test_fingerprint_changes_when_class_changes() -> None:
    f1 = _minimal_finding()
    f2 = _minimal_finding()
    f2["class"] = "ssrf"
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_fingerprint_changes_when_invariant_changes() -> None:
    f1 = _minimal_finding()
    f2 = _minimal_finding()
    f2["boundary"]["security_invariant"] = "Different invariant"
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_fingerprint_changes_when_root_cause_changes() -> None:
    f1 = _minimal_finding()
    f2 = _minimal_finding()
    f2["root_cause"] = "Different cause"
    assert compute_fingerprint(f1) != compute_fingerprint(f2)


def test_fingerprint_changes_when_source_or_sink_changes() -> None:
    f1 = _minimal_finding()
    f2 = _minimal_finding()
    f2["trace"][0]["symbol"] = "differentEntry"
    assert compute_fingerprint(f1) != compute_fingerprint(f2)

    f3 = _minimal_finding()
    f3["trace"][-1]["symbol"] = "differentSink"
    assert compute_fingerprint(f1) != compute_fingerprint(f3)


def test_fingerprint_normalizes_whitespace_and_case() -> None:
    f1 = FindingFingerprint.from_inputs(
        vuln_class="IDOR", invariant="Tenant A cannot access Tenant B objects",
        root_cause="  Missing   ownership  check  ",
        source_symbol="getInvoice", sink_symbol="findById", boundary_type="tenant_isolation",
    )
    f2 = FindingFingerprint.from_inputs(
        vuln_class="idor", invariant="tenant a cannot access tenant b objects",
        root_cause="missing ownership check", source_symbol="getInvoice",
        sink_symbol="findById", boundary_type="TENANT_ISOLATION",
    )
    assert f1.value == f2.value


def test_fingerprint_rejects_empty_vuln_class() -> None:
    with pytest.raises(ValueError):
        FindingFingerprint.from_inputs(
            vuln_class="", invariant="x", root_cause="x",
            source_symbol="x", sink_symbol="x", boundary_type="x",
        )


def test_fingerprint_rejects_empty_source_symbol() -> None:
    with pytest.raises(ValueError):
        FindingFingerprint.from_inputs(
            vuln_class="x", invariant="x", root_cause="x",
            source_symbol="", sink_symbol="x", boundary_type="x",
        )


def test_fingerprint_allows_optional_empty_for_rejected() -> None:
    """invariant/root_cause/boundary_type may be empty for rejected findings."""
    fp = FindingFingerprint.from_inputs(
        vuln_class="rce", invariant="", root_cause="",
        source_symbol="exec", sink_symbol="exec", boundary_type="",
    )
    assert fp.value.startswith("v1:")


def test_dedupe_findings_drops_duplicates() -> None:
    f1 = _minimal_finding()
    f2 = _minimal_finding(id="F-002")  # same content, different id
    f3 = _minimal_finding()
    f3["class"] = "ssrf"  # different
    out = dedupe_findings([f1, f2, f3])
    assert len(out) == 2
    fp_set = {compute_fingerprint(f) for f in out}
    assert len(fp_set) == 2