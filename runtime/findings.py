"""Canonical finding store (Spec §10, §11).

``findings.json`` is the canonical source of truth for every finding a
mini-audit run produces. The markdown report is *generated* from this
canonical store, never hand-edited alongside it.

Top-level verdict model (Spec §10.2):

    confirmed
    needs_validation
    rejected

The 11+ permission-delta categories collapse into ``disposition_reason``:

    by_design
    equivalent_capability
    post_compromise
    invented_permission
    keyword_cvss
    hypothetical_chain
    default_state_confusion
    speculative_client_behavior
    fix_as_proof
    insufficient_evidence
    hardening_only
    duplicate
    out_of_scope

The store is the only writer of ``findings.json``. Sub-agents write into
their own ``agents/<id>/scratch/`` and the runtime promotes validated
finding drafts into the canonical store via :meth:`FindingStore.upsert`.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from .atomic_io import AtomicIOError, read_json_or_corrupt, write_json_atomic
from .fingerprint import compute_fingerprint

FINDING_SCHEMA_VERSION = 1

VERDICT_CONFIRMED = "confirmed"
VERDICT_NEEDS_VALIDATION = "needs_validation"
VERDICT_REJECTED = "rejected"

VERDICTS: frozenset[str] = frozenset({VERDICT_CONFIRMED, VERDICT_NEEDS_VALIDATION, VERDICT_REJECTED})

DISPOSITION_REASONS: frozenset[str] = frozenset({
    "by_design",
    "equivalent_capability",
    "post_compromise",
    "invented_permission",
    "keyword_cvss",
    "hypothetical_chain",
    "default_state_confusion",
    "speculative_client_behavior",
    "fix_as_proof",
    "insufficient_evidence",
    "hardening_only",
    "duplicate",
    "out_of_scope",
})

SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


class FindingValidationError(ValueError):
    """Raised when a finding dict fails canonical validation."""


REQUIRED_TOP_FIELDS = (
    "id",
    "fingerprint",
    "verdict",
    "class",
    "title",
    "summary",
    "source_ref",
)


def _now_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def validate_finding(finding: Mapping[str, Any]) -> None:
    """Validate a finding against the canonical schema.

    Schema lives in ``schemas/finding.schema.json``; this function
    implements a stdlib-only fallback validator that covers the same
    fields, plus additional invariants the schema cannot express.
    """
    if not isinstance(finding, Mapping):
        raise FindingValidationError(f"finding must be a mapping, got {type(finding).__name__}")

    for field in REQUIRED_TOP_FIELDS:
        if field not in finding or finding[field] in (None, ""):
            raise FindingValidationError(f"missing required field: {field}")

    verdict = finding.get("verdict")
    if verdict not in VERDICTS:
        raise FindingValidationError(f"invalid verdict: {verdict!r}")

    if verdict == VERDICT_REJECTED:
        reason = finding.get("disposition_reason")
        if reason not in DISPOSITION_REASONS:
            raise FindingValidationError(
                f"rejected finding requires disposition_reason in {sorted(DISPOSITION_REASONS)}; got {reason!r}"
            )

    sev = (finding.get("severity") or {})
    overall = sev.get("overall") if isinstance(sev, Mapping) else None
    if verdict == VERDICT_CONFIRMED:
        if overall not in SEVERITIES:
            raise FindingValidationError(
                f"confirmed finding requires severity.overall in {sorted(SEVERITIES)}; got {overall!r}"
            )

    boundary = finding.get("boundary") or {}
    if verdict == VERDICT_CONFIRMED:
        if not isinstance(boundary, Mapping) or "type" not in boundary:
            raise FindingValidationError("confirmed finding requires boundary.type")
        if not boundary.get("security_invariant"):
            raise FindingValidationError("confirmed finding requires boundary.security_invariant")
        if boundary.get("crossed") is not True:
            raise FindingValidationError("confirmed finding requires boundary.crossed == true")

    trace = finding.get("trace") or []
    if not isinstance(trace, list) or not trace:
        raise FindingValidationError("finding requires non-empty trace list")

    source_ref = finding.get("source_ref") or {}
    if not isinstance(source_ref, Mapping) or not source_ref.get("commit"):
        raise FindingValidationError("finding requires source_ref.commit")

    # Invariant: fingerprint matches canonical recomputation
    expected_fp = compute_fingerprint(finding)
    if finding.get("fingerprint") != expected_fp:
        raise FindingValidationError(
            f"finding fingerprint mismatch: declared={finding.get('fingerprint')!r} "
            f"computed={expected_fp!r}"
        )


@dataclass
class FindingStore:
    """Canonical findings store backed by ``findings.json``."""

    audit_id: str
    findings: list[dict[str, Any]] = None  # type: ignore[assignment]
    lock: threading.RLock = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.findings is None:
            self.findings = []
        if self.lock is None:
            self.lock = threading.RLock()

    @classmethod
    def empty(cls, *, audit_id: str) -> "FindingStore":
        return cls(audit_id=audit_id, findings=[], lock=threading.RLock())

    @classmethod
    def load(cls, path: os.PathLike[str] | str) -> "FindingStore":
        try:
            data = read_json_or_corrupt(path)
        except FileNotFoundError:
            return cls(audit_id="", findings=[], lock=threading.RLock())
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "FindingStore":
        audit_id = data.get("audit_id", "")
        items = data.get("findings", [])
        if not isinstance(items, list):
            raise FindingValidationError("findings.json: 'findings' must be a list")
        store = cls(audit_id=audit_id, findings=list(items), lock=threading.RLock())
        for f in store.findings:
            validate_finding(f)
        return store

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "audit_id": self.audit_id,
            "findings": list(self.findings),
        }

    def save(self, path: os.PathLike[str] | str) -> None:
        with self.lock:
            write_json_atomic(path, self.to_dict())

    # ---- CRUD ----

    def upsert(self, finding: Mapping[str, Any], *, validate: bool = True) -> dict[str, Any]:
        """Insert or replace a finding by fingerprint.

        The same bug may be rediscovered across revisits; we want one row,
        not N rows. We key by fingerprint rather than id so the merge is
        stable across renumbering.
        """
        finding_dict = dict(finding)
        if validate:
            validate_finding(finding_dict)
        fp = finding_dict["fingerprint"]
        with self.lock:
            for i, existing in enumerate(self.findings):
                if existing.get("fingerprint") == fp:
                    # Preserve provenance: union of trace steps, take newer text.
                    merged = self._merge(existing, finding_dict)
                    self.findings[i] = merged
                    return merged
            self.findings.append(finding_dict)
            return finding_dict

    def remove(self, fingerprint: str) -> bool:
        with self.lock:
            before = len(self.findings)
            self.findings = [f for f in self.findings if f.get("fingerprint") != fingerprint]
            return len(self.findings) < before

    def get(self, fingerprint: str) -> Optional[dict[str, Any]]:
        with self.lock:
            for f in self.findings:
                if f.get("fingerprint") == fingerprint:
                    return f
        return None

    def filter(self, *, verdict: Optional[str] = None, min_severity: Optional[str] = None,
               cls: Optional[str] = None) -> list[dict[str, Any]]:
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        threshold = sev_rank.get(min_severity, 0) if min_severity else 0
        with self.lock:
            out = []
            for f in self.findings:
                if verdict and f.get("verdict") != verdict:
                    continue
                if cls and f.get("class") != cls:
                    continue
                if min_severity:
                    overall = (f.get("severity") or {}).get("overall")
                    if sev_rank.get(overall, -1) < threshold:
                        continue
                out.append(f)
            return out

    def stats(self) -> dict[str, int]:
        with self.lock:
            counts = {v: 0 for v in VERDICTS}
            sev_counts = {s: 0 for s in SEVERITIES}
            for f in self.findings:
                v = f.get("verdict")
                if v in counts:
                    counts[v] += 1
                overall = (f.get("severity") or {}).get("overall")
                if overall in sev_counts:
                    sev_counts[overall] += 1
            return {
                "total": len(self.findings),
                **counts,
                **{f"severity_{k}": v for k, v in sev_counts.items()},
            }

    @staticmethod
    def _merge(existing: Mapping[str, Any], new: Mapping[str, Any]) -> dict[str, Any]:
        """Merge two findings with the same fingerprint, preferring the newer.

        Trace steps are unioned by file+line+kind+symbol so evidence
        accumulates without duplication. Other fields are taken from the
        newer finding unless empty.
        """
        def prefer(*values: Any) -> Any:
            for v in values:
                if v not in (None, "", [], {}):
                    return v
            return values[-1]

        merged: dict[str, Any] = dict(existing)
        for k, v in new.items():
            merged[k] = prefer(v, merged.get(k))

        # Union trace steps
        seen_keys = set()
        merged_trace: list[dict[str, Any]] = []
        for src in (existing.get("trace") or [], new.get("trace") or []):
            for step in src:
                if not isinstance(step, Mapping):
                    continue
                key = (step.get("kind"), step.get("file"), step.get("line"), step.get("symbol"))
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                merged_trace.append(dict(step))
        merged["trace"] = merged_trace

        merged["updated_at"] = _now_iso()
        return merged


def merge_stores(*stores: FindingStore) -> FindingStore:
    """Merge multiple stores into one, deduplicating by fingerprint."""
    target = FindingStore.empty(audit_id="")
    for store in stores:
        for f in store.findings:
            target.upsert(f)
    return target