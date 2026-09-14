"""Export canonical findings to JSON, Markdown, and SARIF (Spec §34).

The canonical source is ``findings.json``. Markdown and SARIF outputs are
*derived*, not edited by hand alongside the canonical store.

Filters:

    --verdict confirmed
    --min-severity high
    --class idor
    --since <timestamp>

SARIF 2.1.0 output is generated so the result can be uploaded to GitHub
Code Scanning, DefectDojo, or any SARIF-aware triage platform.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

from .findings import (
    SEVERITIES,
    VERDICT_CONFIRMED,
    VERDICT_NEEDS_VALIDATION,
    VERDICT_REJECTED,
    FindingStore,
    SEVERITIES as _SEV,  # noqa: F401
)
from .fingerprint import compute_fingerprint

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
SARIF_TOOL_NAME = "mini-audit"

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _normalize_iso(ts: str) -> str:
    if not ts:
        return ""
    try:
        # Already ISO?
        return _dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return ts


def _filter_findings(store: FindingStore, *, verdict: Optional[str] = None,
                     min_severity: Optional[str] = None,
                     cls: Optional[str] = None,
                     since: Optional[str] = None) -> list[dict[str, Any]]:
    since_dt: Optional[_dt.datetime] = None
    if since:
        try:
            since_dt = _dt.datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            since_dt = None

    threshold = _SEVERITY_RANK.get(min_severity, 0) if min_severity else 0
    out: list[dict[str, Any]] = []
    for f in store.findings:
        if verdict and f.get("verdict") != verdict:
            continue
        if cls and f.get("class") != cls:
            continue
        overall = (f.get("severity") or {}).get("overall")
        if threshold and _SEVERITY_RANK.get(overall, -1) < threshold:
            continue
        if since_dt:
            updated = f.get("updated_at") or f.get("source_ref", {}).get("captured_at")
            if updated:
                try:
                    if _dt.datetime.fromisoformat(updated.replace("Z", "+00:00")) < since_dt:
                        continue
                except ValueError:
                    pass
        out.append(f)
    return out


def export_json(store: FindingStore, *, path: os.PathLike[str] | str,
                verdict: Optional[str] = None, min_severity: Optional[str] = None,
                cls: Optional[str] = None, since: Optional[str] = None) -> int:
    findings = _filter_findings(store, verdict=verdict, min_severity=min_severity, cls=cls, since=since)
    payload = {
        "schema_version": 1,
        "audit_id": store.audit_id,
        "exported_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "filter": {
            "verdict": verdict,
            "min_severity": min_severity,
            "class": cls,
            "since": since,
        },
        "findings": findings,
        "stats": store.stats(),
    }
    Path(path).write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(findings)


def _md_severity_badge(severity: str) -> str:
    return {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🔵 LOW",
        "info": "⚪ INFO",
    }.get(severity, severity.upper())


def export_markdown(store: FindingStore, *, path: os.PathLike[str] | str,
                    verdict: Optional[str] = None, min_severity: Optional[str] = None,
                    cls: Optional[str] = None, since: Optional[str] = None) -> int:
    findings = _filter_findings(store, verdict=verdict, min_severity=min_severity, cls=cls, since=since)
    findings_sorted = sorted(
        findings,
        key=lambda f: (-_SEVERITY_RANK.get((f.get("severity") or {}).get("overall"), -1),
                       f.get("id", "")),
    )
    lines: list[str] = []
    lines.append("# mini-audit report")
    lines.append("")
    lines.append(f"- audit_id: `{store.audit_id}`")
    lines.append(f"- generated_at: `{_dt.datetime.now(_dt.timezone.utc).isoformat()}`")
    stats = store.stats()
    lines.append(f"- total findings: {stats.get('total', 0)}")
    lines.append(f"- confirmed: {stats.get('confirmed', 0)}")
    lines.append(f"- needs_validation: {stats.get('needs_validation', 0)}")
    lines.append(f"- rejected: {stats.get('rejected', 0)}")
    lines.append("")
    if not findings_sorted:
        lines.append("_No findings match the active filters._")
    for f in findings_sorted:
        sev = (f.get("severity") or {}).get("overall", "info")
        lines.append(f"## {f.get('id', '')} — {f.get('title', '')}")
        lines.append("")
        lines.append(f"- **verdict**: `{f.get('verdict')}`")
        lines.append(f"- **severity**: {_md_severity_badge(sev)}")
        lines.append(f"- **class**: `{f.get('class')}`")
        lines.append(f"- **fingerprint**: `{f.get('fingerprint')}`")
        lines.append("")
        lines.append(f.get("summary", ""))
        lines.append("")
        boundary = f.get("boundary") or {}
        if boundary:
            lines.append(f"**Boundary**: `{boundary.get('type','')}` — {boundary.get('security_invariant','')}")
            lines.append("")
        trace = f.get("trace") or []
        if trace:
            lines.append("### Trace")
            lines.append("")
            for step in trace:
                lines.append(f"- `{step.get('kind','')}` `{step.get('file','')}:{step.get('line','')}` — `{step.get('symbol','')}`")
            lines.append("")
        v = f.get("verification") or {}
        if v:
            lines.append("### Verification")
            lines.append("")
            lines.append(f"- technical_verifier: `{v.get('technical_verifier','')}`")
            lines.append(f"- policy_judge: `{v.get('policy_judge','')}`")
            lines.append(f"- independence: `{v.get('independence','')}`")
            lines.append("")
        lines.append("---")
        lines.append("")

    Path(path).write_text("\n".join(lines), encoding="utf-8")
    return len(findings)


def export_sarif(store: FindingStore, *, path: os.PathLike[str] | str,
                 verdict: Optional[str] = None, min_severity: Optional[str] = None,
                 cls: Optional[str] = None, since: Optional[str] = None) -> int:
    findings = _filter_findings(store, verdict=verdict, min_severity=min_severity, cls=cls, since=since)
    sarif_results = []
    rules_index: dict[str, dict[str, Any]] = {}
    for f in findings:
        rule_id = f"mini-audit/{f.get('class','uncategorized')}"
        if rule_id not in rules_index:
            rules_index[rule_id] = {
                "id": rule_id,
                "name": f.get("class", "uncategorized"),
                "shortDescription": {"text": f.get("class", "uncategorized")},
                "fullDescription": {"text": f.get("title", "")},
                "help": {"text": f.get("summary", "")},
                "defaultConfiguration": {"level": _sarif_level(f.get("verdict"))},
            }
        result = {
            "ruleId": rule_id,
            "level": _sarif_level(f.get("verdict")),
            "message": {"text": f.get("summary") or f.get("title") or ""},
            "properties": {
                "fingerprint": f.get("fingerprint"),
                "verdict": f.get("verdict"),
                "severity": (f.get("severity") or {}).get("overall"),
                "audit_id": store.audit_id,
                "tags": ["mini-audit", f.get("class") or "uncategorized"],
            },
        }
        # Use the first trace entrypoint for the location if available.
        trace = f.get("trace") or []
        if trace:
            entry = next((t for t in trace if t.get("kind") == "entrypoint"), trace[0])
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": entry.get("file", "")},
                    "region": {"startLine": int(entry.get("line") or 1)},
                },
                "logicalLocations": [{"name": entry.get("symbol", ""), "kind": "function"}],
            }]
        sarif_results.append(result)

    sarif = {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": SARIF_TOOL_NAME,
                        "version": "1.0.0",
                        "informationUri": "https://github.com/Rinne666/mini-audit-skill",
                        "rules": list(rules_index.values()),
                    }
                },
                "results": sarif_results,
                "properties": {
                    "audit_id": store.audit_id,
                    "exported_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
                },
            }
        ],
    }
    Path(path).write_text(json.dumps(sarif, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return len(findings)


def _sarif_level(verdict: Optional[str]) -> str:
    return {
        VERDICT_CONFIRMED: "error",
        VERDICT_NEEDS_VALIDATION: "warning",
        VERDICT_REJECTED: "note",
    }.get(verdict or "", "note")


class Exporter:
    """Dispatch export by format string."""

    def __init__(self, store: FindingStore) -> None:
        self.store = store

    def export(self, *, fmt: str, path: os.PathLike[str] | str,
               verdict: Optional[str] = None, min_severity: Optional[str] = None,
               cls: Optional[str] = None, since: Optional[str] = None) -> int:
        fmt = fmt.lower()
        if fmt == "json":
            return export_json(self.store, path=path, verdict=verdict, min_severity=min_severity, cls=cls, since=since)
        if fmt == "md" or fmt == "markdown":
            return export_markdown(self.store, path=path, verdict=verdict, min_severity=min_severity, cls=cls, since=since)
        if fmt == "sarif":
            return export_sarif(self.store, path=path, verdict=verdict, min_severity=min_severity, cls=cls, since=since)
        raise ValueError(f"unknown export format: {fmt!r}")