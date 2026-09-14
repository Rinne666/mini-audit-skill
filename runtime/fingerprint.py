"""Stable finding fingerprints (Spec §12).

Finding IDs are unstable across runs and audit modes. We need a fingerprint
that survives wording changes, finding renumbering, and severity drift so
the same bug across revisit/reuse/variant produces the same identifier.

Recommended fingerprint inputs (Spec §12):

    vulnerability class
    security invariant
    root cause
    primary source symbol
    primary sink symbol
    boundary type

Forbidden inputs (Spec §12):

    line number
    finding ID
    report wording
    severity
    timestamp

The fingerprint is computed as:

    v = "v1"
    canonical = "|".join([
        v,
        normalize(vuln_class),
        normalize(invariant),
        normalize(root_cause),
        source_symbol,
        sink_symbol,
        boundary_type,
    ])
    fingerprint = sha256(canonical)
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

FINGERPRINT_VERSION = "v1"

# Punctuation and whitespace that do not affect semantic identity.
_WHITESPACE_RE = re.compile(r"\s+")
_NON_ALNUM_RE = re.compile(r"[^a-z0-9_\-./:]")


def _normalize(value: str) -> str:
    """Lowercase, collapse whitespace, strip non-semantic punctuation."""
    if value is None:
        return ""
    lowered = value.strip().lower()
    lowered = _WHITESPACE_RE.sub(" ", lowered)
    # Keep dot, slash, colon, hyphen, underscore for source paths and symbols.
    # Drop everything else.
    cleaned = _NON_ALNUM_RE.sub("", lowered.replace(" ", ""))
    return cleaned


def _required(value: str, *, field: str, allow_empty: bool = False) -> str:
    """Reject empty inputs unless *allow_empty* is set.

    Identity-critical fields (vuln_class, source_symbol, sink_symbol) must
    always be present. Semantic fields (invariant, root_cause,
    boundary_type) may be empty for rejected findings that have no
    broken-invariant semantics.
    """
    if allow_empty:
        return str(value) if value is not None else ""
    if value is None or not str(value).strip():
        raise ValueError(f"fingerprint input '{field}' must be non-empty")
    return str(value)


@dataclass(frozen=True)
class FindingFingerprint:
    """Stable, content-derived identifier for a finding."""

    value: str
    version: str = FINGERPRINT_VERSION

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value

    @classmethod
    def from_inputs(cls, *, vuln_class: str, invariant: str, root_cause: str,
                    source_symbol: str, sink_symbol: str, boundary_type: str,
                    allow_empty_optional: bool = True) -> "FindingFingerprint":
        canonical = "|".join([
            FINGERPRINT_VERSION,
            _normalize(_required(vuln_class, field="vuln_class")),
            _normalize(_required(invariant, field="invariant", allow_empty=allow_empty_optional)),
            _normalize(_required(root_cause, field="root_cause", allow_empty=allow_empty_optional)),
            _normalize(_required(source_symbol, field="source_symbol")),
            _normalize(_required(sink_symbol, field="sink_symbol")),
            _normalize(_required(boundary_type, field="boundary_type", allow_empty=allow_empty_optional)),
        ])
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return cls(value=f"{FINGERPRINT_VERSION}:{digest}", version=FINGERPRINT_VERSION)

    @classmethod
    def from_finding(cls, finding: Mapping[str, Any]) -> "FindingFingerprint":
        """Derive fingerprint from a canonical finding dict."""
        cls_name = finding.get("class") or finding.get("vuln_class") or ""
        boundary = (finding.get("boundary") or {}).get("type") or ""
        invariant = (finding.get("boundary") or {}).get("security_invariant") or ""
        root_cause = finding.get("root_cause") or ""
        trace = finding.get("trace") or []
        source_symbol = ""
        sink_symbol = ""
        for step in trace:
            kind = step.get("kind") if isinstance(step, Mapping) else None
            symbol = step.get("symbol", "") if isinstance(step, Mapping) else ""
            if kind == "entrypoint" and not source_symbol:
                source_symbol = symbol or f"{step.get('file','')}:{step.get('line','')}"
            elif kind == "sink" and not sink_symbol:
                sink_symbol = symbol or f"{step.get('file','')}:{step.get('line','')}"
        if not source_symbol:
            source_symbol = (finding.get("source_ref") or {}).get("symbol", "") or "unknown-source"
        if not sink_symbol:
            sink_symbol = "unknown-sink"
        return cls.from_inputs(
            vuln_class=cls_name,
            invariant=invariant,
            root_cause=root_cause,
            source_symbol=source_symbol,
            sink_symbol=sink_symbol,
            boundary_type=boundary,
        )


def compute_fingerprint(finding: Mapping[str, Any]) -> str:
    """Convenience wrapper returning the fingerprint string."""
    return FindingFingerprint.from_finding(finding).value


def dedupe_findings(findings: Iterable[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    """Deduplicate findings by stable fingerprint, keeping the first occurrence.

    Mutates nothing; returns a list of the originals in their input order.
    """
    seen: set[str] = set()
    out: list[Mapping[str, Any]] = []
    for f in findings:
        fp = compute_fingerprint(f)
        if fp in seen:
            continue
        seen.add(fp)
        out.append(f)
    return out