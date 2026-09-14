"""Phase gate runner (Spec §9).

A gate is a deterministic, side-effect-free predicate over the artifacts
that a phase is supposed to produce. Forbidden pattern:

    file exists → complete

A real gate checks:

    existence
    schema
    size
    parseability
    semantic consistency
    source reference validity

Gates are declared declaratively (YAML/JSON) so that they are reviewable
and unit-testable in isolation from agent prompts.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from .atomic_io import sha256_file


class GateError(RuntimeError):
    """Raised when a gate fails."""


@dataclass
class GateFailure:
    """One specific reason a gate failed."""

    check: str
    path: Optional[str]
    message: str


@dataclass
class GateResult:
    """Aggregate result of running one or more gates."""

    name: str
    passed: bool
    failures: list[GateFailure] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add_failure(self, check: str, path: Optional[str], message: str) -> None:
        self.passed = False
        self.failures.append(GateFailure(check=check, path=path, message=message))

    def add_note(self, note: str) -> None:
        self.notes.append(note)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "failures": [{"check": f.check, "path": f.path, "message": f.message} for f in self.failures],
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Check primitives
# ---------------------------------------------------------------------------


def check_exists(path: str) -> tuple[bool, str]:
    p = Path(path)
    if not p.exists():
        return False, f"missing: {path}"
    if not p.is_file():
        return False, f"not a regular file: {path}"
    return True, ""


def check_min_size(path: str, min_bytes: int = 1) -> tuple[bool, str]:
    size = Path(path).stat().st_size
    if size < min_bytes:
        return False, f"file too small ({size} < {min_bytes}): {path}"
    return True, ""


def check_json_parseable(path: str) -> tuple[bool, str, Optional[Any]]:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return False, f"json parse error: {exc}", None
    return True, "", data


def check_max_size(path: str, max_bytes: int = 50 * 1024 * 1024) -> tuple[bool, str]:
    """Sanity bound: refuse to load a pathologically large artifact."""
    size = Path(path).stat().st_size
    if size > max_bytes:
        return False, f"file too large ({size} > {max_bytes}): {path}"
    return True, ""


def check_glob_matches(pattern: str) -> tuple[bool, str, list[str]]:
    from glob import glob

    matches = sorted(glob(pattern))
    if not matches:
        return False, f"glob matched 0 files: {pattern}", []
    return True, "", matches


# ---------------------------------------------------------------------------
# Semantic checks (named predicates the gate definition can reference)
# ---------------------------------------------------------------------------

SEMANTIC_CHECKS: dict[str, Callable[[Mapping[str, Any], dict[str, Any]], tuple[bool, str]]] = {}


def register_semantic(name: str) -> Callable[[Callable[..., tuple[bool, str]]], Callable[..., tuple[bool, str]]]:
    """Decorator for registering a named semantic check."""

    def deco(fn: Callable[..., tuple[bool, str]]) -> Callable[..., tuple[bool, str]]:
        SEMANTIC_CHECKS[name] = fn
        return fn

    return deco


def run_semantic(name: str, data: Mapping[str, Any], ctx: Optional[dict[str, Any]] = None) -> tuple[bool, str]:
    ctx = ctx or {}
    fn = SEMANTIC_CHECKS.get(name)
    if fn is None:
        return False, f"unknown semantic check: {name}"
    return fn(data, ctx)


@register_semantic("non_empty")
def _check_non_empty(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    if not data:
        return False, "data is empty"
    return True, ""


@register_semantic("every_chamber_closed")
def _check_every_chamber_closed(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    chambers = data.get("chambers") or []
    if not isinstance(chambers, list):
        return False, "'chambers' must be a list"
    open_chambers = [c for c in chambers if (c.get("debate_status") if isinstance(c, Mapping) else None) != "closed"]
    if open_chambers:
        return False, f"{len(open_chambers)} chamber(s) not closed: {[c.get('id') for c in open_chambers]}"
    return True, ""


@register_semantic("every_valid_candidate_has_boundary_sentence")
def _check_boundary_sentence(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    valid = data.get("valid_candidates") or []
    if not isinstance(valid, list):
        return False, "'valid_candidates' must be a list"
    bad = []
    for c in valid:
        if not isinstance(c, Mapping):
            continue
        bs = (c.get("boundary_sentence") or "").strip()
        if not bs:
            bad.append(c.get("candidate_id") or c.get("id") or "?")
    if bad:
        return False, f"{len(bad)} candidate(s) missing boundary_sentence: {bad}"
    return True, ""


@register_semantic("every_confirmed_has_verifier")
def _check_every_confirmed_has_verifier(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    """Applied to findings.json: every confirmed finding must have a verifier."""
    findings = data.get("findings") or []
    if not isinstance(findings, list):
        return False, "'findings' must be a list"
    bad = []
    for f in findings:
        if not isinstance(f, Mapping):
            continue
        if f.get("verdict") != "confirmed":
            continue
        v = f.get("verification") or {}
        if not (isinstance(v, Mapping) and v.get("technical_verifier")):
            bad.append(f.get("id") or f.get("fingerprint") or "?")
    if bad:
        return False, f"{len(bad)} confirmed finding(s) missing technical_verifier: {bad}"
    return True, ""


@register_semantic("coverage_no_planned")
def _check_coverage_no_planned(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    units = data.get("units") or []
    if not isinstance(units, list):
        return False, "'units' must be a list"
    unresolved = [u for u in units if isinstance(u, Mapping) and u.get("status") in ("planned", "in_progress")]
    if unresolved:
        return False, f"{len(unresolved)} coverage unit(s) still planned/in_progress"
    return True, ""


@register_semantic("audit_state_terminal_phases")
def _check_audit_state_terminal(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    phases = data.get("phases") or {}
    required = ctx.get("required_phases") or []
    bad = []
    for name in required:
        p = phases.get(name) or {}
        if not isinstance(p, Mapping):
            bad.append(f"{name} (missing)")
            continue
        if p.get("status") not in ("complete", "skipped"):
            bad.append(f"{name} ({p.get('status')})")
    if bad:
        return False, f"non-terminal phases: {bad}"
    return True, ""


# ---------------------------------------------------------------------------
# Gate definition + driver
# ---------------------------------------------------------------------------


@dataclass
class GateDefinition:
    """Declarative phase gate (Spec §9 example)."""

    name: str
    required: list[dict[str, Any]] = field(default_factory=list)
    required_glob: list[str] = field(default_factory=list)
    semantic_checks: list[str] = field(default_factory=list)
    schema_refs: dict[str, str] = field(default_factory=dict)  # path -> schema path

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "GateDefinition":
        return cls(
            name=data.get("name", ""),
            required=list(data.get("required", [])),
            required_glob=list(data.get("required_glob", [])),
            semantic_checks=list(data.get("semantic_checks", [])),
            schema_refs=dict(data.get("schema_refs", {})),
        )


class GateRunner:
    """Apply a GateDefinition to a set of on-disk artifacts."""

    def __init__(self, *, workdir: os.PathLike[str] | str = ".") -> None:
        self.workdir = Path(workdir).resolve()

    def run(self, gate: GateDefinition, *, semantic_data: Optional[Mapping[str, Mapping[str, Any]]] = None,
            ctx: Optional[dict[str, Any]] = None) -> GateResult:
        ctx = ctx or {}
        semantic_data = semantic_data or {}
        result = GateResult(name=gate.name, passed=True)

        # 1. existence + size + parseability per required file
        for req in gate.required:
            path = req.get("path")
            min_bytes = int(req.get("min_bytes", 1))
            if not path:
                result.add_failure("required.path", None, "required entry missing 'path'")
                continue
            abs_path = path if os.path.isabs(path) else str(self.workdir / path)
            ok, msg = check_exists(abs_path)
            if not ok:
                result.add_failure("existence", path, msg)
                continue
            ok, msg = check_max_size(abs_path)
            if not ok:
                result.add_failure("size", path, msg)
                continue
            ok, msg = check_min_size(abs_path, min_bytes)
            if not ok:
                result.add_failure("size", path, msg)
                continue
            if req.get("parse_json"):
                ok, msg, data = check_json_parseable(abs_path)
                if not ok:
                    result.add_failure("parseability", path, msg)
                    continue
                semantic_data[path] = data

        # 2. glob matches
        for pattern in gate.required_glob:
            ok, msg, matches = check_glob_matches(str(self.workdir / pattern))
            if not ok:
                result.add_failure("required_glob", pattern, msg)
                continue
            result.add_note(f"glob {pattern} matched {len(matches)} file(s)")

        # 3. semantic checks
        for check_name in gate.semantic_checks:
            # Try each data source until one passes (semantic checks are
            # typically tied to one artifact; we just try them all so the
            # gate definition stays declarative).
            ran = False
            for src_path, src_data in semantic_data.items():
                ok, msg = run_semantic(check_name, src_data, ctx)
                if ok:
                    ran = True
                    break
                # try the next
            if not ran and semantic_data:
                result.add_failure("semantic", None, f"semantic check {check_name!r} failed for all sources")
            elif not ran:
                result.add_failure("semantic", None, f"no data provided for semantic check {check_name!r}")

        return result


# Built-in gate library — minimal defaults for the standard mini-audit phases.
DEFAULT_PHASE_GATES: dict[str, dict[str, Any]] = {
    "L1": {
        "name": "L1",
        "required": [
            {"path": "mini-audit/attack-surface/intent-corpus.json", "parse_json": True},
        ],
        "semantic_checks": ["non_empty"],
    },
    "L2": {
        "name": "L2",
        "required": [
            {"path": "mini-audit/context/knowledge-base.md", "min_bytes": 100},
        ],
    },
    "L3": {
        "name": "L3",
        "required": [
            {"path": "mini-audit/scanner/capabilities.json", "parse_json": True},
        ],
    },
    "L4": {
        "name": "L4",
        "required": [
            {"path": "mini-audit/env/runtime-summary.json", "parse_json": True},
        ],
    },
    "L5": {
        "name": "L5",
        "required_glob": ["mini-audit/probe-workspace/*/probe-summary.md"],
    },
    "L6": {
        "name": "L6",
        "required_glob": ["mini-audit/chamber-workspace/*/debate.json"],
        "semantic_checks": ["every_chamber_closed", "every_valid_candidate_has_boundary_sentence"],
    },
    "L6b": {
        "name": "L6b",
        "required_glob": ["mini-audit/findings-draft/*/draft.md"],
    },
    "L6c": {
        "name": "L6c",
        "required_glob": ["mini-audit/findings/*/poc.sh", "mini-audit/findings/*/evidence/exploit.log"],
    },
    "L7": {
        "name": "L7",
        "required": [
            {"path": "mini-audit/findings.json", "parse_json": True},
            {"path": "mini-audit/final-audit-report.md", "min_bytes": 100},
            {"path": "mini-audit/coverage-ledger.json", "parse_json": True},
        ],
        "semantic_checks": [
            "every_confirmed_has_verifier",
            "coverage_no_planned",
            "audit_state_terminal_phases",
        ],
    },
}


def gate_for(phase: str) -> GateDefinition:
    if phase not in DEFAULT_PHASE_GATES:
        raise GateError(f"no default gate defined for phase {phase!r}")
    return GateDefinition.from_dict(DEFAULT_PHASE_GATES[phase])