"""SARIF normalization (Spec §28).

Scanner alerts are *never* confirmed findings. They become candidates
that the LLM (or a deterministic triager) must evaluate. This module
parses SARIF 2.1.0 output from Semgrep / CodeQL / Gitleaks / etc. and
emits the canonical candidate record:

    {
      "candidate_id": "...",
      "source": "semgrep",
      "rule_id": "...",
      "file": "...",
      "line": 123,
      "message": "...",
      "class": "...",
      "confidence": "...",
      "status": "untriaged"
    }

The optional mapping table (``class_from_rule``) lets us assign a
vulnerability class from the scanner rule id when one is known (e.g.
Semgrep's ``python.lang.security.audit.eval`` → ``code_injection``).
Unknown rules get class="uncategorized" and confidence="unknown" so the
triager cannot accidentally promote them.
"""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional

# Default mapping table — overridable by caller.
DEFAULT_RULE_CLASS_MAP: dict[str, dict[str, str]] = {
    # Semgrep rule id prefix → {class, confidence}
    "python.lang.security.audit.eval": {"class": "code_injection", "confidence": "medium"},
    "python.lang.security.audit.subprocess-shell-true": {"class": "command_injection", "confidence": "medium"},
    "javascript.lang.security.audit.eval": {"class": "code_injection", "confidence": "medium"},
    "javascript.express.security.audit.express-open-redirect": {"class": "open_redirect", "confidence": "low"},
    "java.lang.security.audit.sqli": {"class": "sql_injection", "confidence": "medium"},
    "go.lang.security.audit.sqli": {"class": "sql_injection", "confidence": "medium"},
    "generic.secrets": {"class": "secret_exposure", "confidence": "high"},
}


class SarifError(ValueError):
    """Raised when SARIF input is malformed."""


def _rule_lookup(rule_id: str, mapping: Mapping[str, dict[str, str]]) -> tuple[str, str]:
    """Find (class, confidence) for a rule id, longest-prefix first."""
    if rule_id in mapping:
        entry = mapping[rule_id]
        return entry.get("class", "uncategorized"), entry.get("confidence", "unknown")
    # Try longest-prefix match
    prefix_candidates = sorted(
        [(len(p), p) for p in mapping if rule_id.startswith(p)],
        reverse=True,
    )
    for _, prefix in prefix_candidates:
        entry = mapping[prefix]
        return entry.get("class", "uncategorized"), entry.get("confidence", "unknown")
    return "uncategorized", "unknown"


def _make_candidate_id(source: str, rule_id: str, file_path: str, line: int) -> str:
    h = hashlib.sha256()
    h.update(f"{source}|{rule_id}|{file_path}|{line}".encode("utf-8"))
    return f"cand-{source}-{h.hexdigest()[:12]}"


def normalize_sarif(sarif: Mapping[str, Any], *, source: str = "scanner",
                    rule_class_map: Optional[Mapping[str, dict[str, str]]] = None) -> list[dict[str, Any]]:
    """Convert a parsed SARIF document into candidate records.

    Handles both ``runs[*].tool.driver.rules[*]`` (for rule metadata) and
    ``runs[*].results[*]`` (for the actual findings). A result without a
    matching rule still produces a candidate, just with ``class="uncategorized"``.
    """
    if not isinstance(sarif, Mapping):
        raise SarifError("SARIF document must be a JSON object")
    runs = sarif.get("runs") or []
    if not isinstance(runs, list):
        raise SarifError("SARIF.runs must be a list")
    rule_map = rule_class_map if rule_class_map is not None else DEFAULT_RULE_CLASS_MAP

    candidates: list[dict[str, Any]] = []
    for run in runs:
        if not isinstance(run, Mapping):
            continue
        driver = (run.get("tool") or {}).get("driver") or {}
        rules_index: dict[str, Mapping[str, Any]] = {}
        for rule in driver.get("rules", []) or []:
            rid = rule.get("id")
            if rid:
                rules_index[rid] = rule

        for result in run.get("results", []) or []:
            if not isinstance(result, Mapping):
                continue
            rule_id = result.get("ruleId") or ""
            message = result.get("message", {}).get("text") if isinstance(result.get("message"), Mapping) else result.get("message", "")
            locations = result.get("locations") or []
            file_path = ""
            line = 0
            if locations:
                phys = (locations[0] or {}).get("physicalLocation") or {}
                artifact = phys.get("artifactLocation") or {}
                file_path = artifact.get("uri") or ""
                region = phys.get("region") or {}
                line = int(region.get("startLine") or 0)

            cls_name, confidence = _rule_lookup(rule_id, rule_map)
            short_desc = ""
            tags: list[str] = []
            rule_meta = rules_index.get(rule_id) or {}
            if rule_meta:
                short_desc = (rule_meta.get("shortDescription") or {}).get("text", "") if isinstance(rule_meta.get("shortDescription"), Mapping) else rule_meta.get("shortDescription", "")
                tags = list(((rule_meta.get("properties") or {}).get("tags") or []))
            # Per-result properties.tags may also carry scanner-specific tags.
            result_props = result.get("properties") or {}
            for t in result_props.get("tags") or []:
                if t not in tags:
                    tags.append(t)

            cand = {
                "candidate_id": _make_candidate_id(source, rule_id, file_path, line),
                "source": source,
                "rule_id": rule_id,
                "file": file_path,
                "line": line,
                "message": message or short_desc,
                "class": cls_name,
                "confidence": confidence,
                "tags": tags,
                "status": "untriaged",
                "raw": {
                    "rule_index": rule_id,
                    "rule_short_description": short_desc,
                    "severity": (result.get("level") or (rule_meta.get("defaultConfiguration") or {}).get("level")),
                },
            }
            candidates.append(cand)

    return candidates


def normalize_sarif_file(path: os.PathLike[str] | str, *, source: str = "scanner",
                          rule_class_map: Optional[Mapping[str, dict[str, str]]] = None) -> list[dict[str, Any]]:
    """Load and normalize a SARIF file from disk."""
    p = Path(path)
    data = json.loads(p.read_text(encoding="utf-8"))
    return normalize_sarif(data, source=source, rule_class_map=rule_class_map)


def dedupe_candidates(candidates: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate candidates by candidate_id, keeping the first occurrence."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for c in candidates:
        cid = c.get("candidate_id")
        if cid in seen:
            continue
        seen.add(cid)
        out.append(dict(c))
    return out


def assign_candidate_ids(candidates: Iterable[Mapping[str, Any]], *, source: str = "manual") -> list[dict[str, Any]]:
    """Assign a fresh UUID-based candidate id to records that lack one."""
    out: list[dict[str, Any]] = []
    for c in candidates:
        c = dict(c)
        if not c.get("candidate_id"):
            c["candidate_id"] = f"cand-{source}-{uuid.uuid4().hex[:12]}"
        c.setdefault("status", "untriaged")
        out.append(c)
    return out