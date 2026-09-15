"""Phase gate runner (Spec §9, Hardening v1.1 §3 §4 §5).

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

Gates are declared declaratively (JSON/YAML-shaped dicts) so that they are
reviewable and unit-testable in isolation from agent prompts.

Hardening v1.1 changes
----------------------

§3 — **artifact-bound semantic checks.** A semantic check no longer "runs
against whatever happens to be loaded, passing if any source says yes". Each
check names the artifact it is about::

    "semantic_checks": [
        {"check": "every_confirmed_has_verifier", "source": "mini-audit/findings.json"},
    ]

A check whose declared source is missing or unparseable fails; it can no
longer be satisfied by an unrelated artifact.

§4 — **glob artifacts carry content.** ``required_glob`` entries may request
parsing and aggregation::

    "required_glob": [
        {"pattern": "mini-audit/chamber-workspace/*/debate.json",
         "parse_json": true, "aggregate_as": "chambers"},
    ]

The runner then performs glob → parse JSON → aggregate → semantic
validation, so a gate over a set of files can reason about their contents
instead of just their existence.

§5 — **schema enforcement.** ``required`` entries and glob entries may
declare ``schema`` (a shipped schema name) or ``items_schema`` (applied to
each element of an array property), and the runner validates for real.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Optional

from .atomic_io import sha256_file
from .schema import load_schema_or_none, validate_instance


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


def check_glob_matches(pattern: str, *, min_matches: int = 1) -> tuple[bool, str, list[str]]:
    from glob import glob

    matches = sorted(glob(pattern))
    if len(matches) < max(1, min_matches):
        return False, f"glob matched {len(matches)} file(s), need >= {max(1, min_matches)}: {pattern}", matches
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
    if not chambers:
        return False, "no chambers were aggregated"
    open_chambers = [c for c in chambers if (c.get("debate_status") if isinstance(c, Mapping) else None) != "closed"]
    if open_chambers:
        ids = [c.get("id") or c.get("chamber_id") or "?" for c in open_chambers]
        return False, f"{len(open_chambers)} chamber(s) not closed: {ids}"
    return True, ""


@register_semantic("every_valid_candidate_has_boundary_sentence")
def _check_boundary_sentence(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    """Every VALID candidate must carry a concrete boundary sentence.

    Accepts either a flat ``valid_candidates`` list (single-artifact gate) or
    an aggregated ``chambers`` list whose chambers each carry
    ``valid_candidates`` / ``candidates`` (glob gate, Hardening v1.1 §4).
    """
    valid = data.get("valid_candidates")
    if valid is None:
        valid = []
        chambers = data.get("chambers") or []
        if not isinstance(chambers, list):
            return False, "'chambers' must be a list"
        for chamber in chambers:
            if not isinstance(chamber, Mapping):
                continue
            for candidate in (chamber.get("valid_candidates") or chamber.get("candidates") or []):
                if not isinstance(candidate, Mapping):
                    continue
                verdict = str(candidate.get("verdict") or candidate.get("promotion_recommendation") or "").upper()
                if verdict in ("VALID", "PROMOTE_FOR_VERIFICATION"):
                    valid.append(candidate)
    if not isinstance(valid, list):
        return False, "'valid_candidates' must be a list"
    bad = []
    for c in valid:
        if not isinstance(c, Mapping):
            continue
        bs = (c.get("boundary_sentence") or c.get("boundary") or "").strip()
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
    # Hardening v1.1 §9 — an empty plan must not count as "no unresolved units".
    if not units:
        return False, "coverage plan is empty (unit_count == 0)"
    # v1.1.1: strict. `planning_status` is a required field, so an absent value
    # is itself a failure — a ledger that never recorded its planning lifecycle
    # cannot be treated as having finished it.
    planning_status = data.get("planning_status")
    if planning_status != "complete":
        return False, f"coverage planning is {planning_status!r}, not 'complete'"
    unresolved = [u for u in units if isinstance(u, Mapping) and u.get("status") in ("planned", "in_progress")]
    if unresolved:
        return False, f"{len(unresolved)} coverage unit(s) still planned/in_progress"
    return True, ""


@register_semantic("audit_state_terminal_phases")
def _check_audit_state_terminal(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    phases = data.get("phases") or {}
    # The phase currently being gated is not "already terminal" by definition —
    # it is the one we are deciding about. Excluding it here (as well as at the
    # call site) keeps the check honest when `required_phases` is absent *or*
    # empty, which is the normal shape early in an audit (state.init declares no
    # phases, so completing the first phase leaves no other phase to require).
    current = ctx.get("current_phase")
    explicit = ctx.get("required_phases")
    if explicit is None:
        # No explicit requirement: every declared phase except the current one.
        required = [name for name in phases if name != current]
    else:
        required = [name for name in explicit if name != current]
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


@register_semantic("no_placeholder_text")
def _check_no_placeholder_text(data: Mapping[str, Any], ctx: dict[str, Any]) -> tuple[bool, str]:
    """Guard against 'TBD' / 'TODO' / 'lorem ipsum' masquerading as evidence."""
    blob = json.dumps(data, ensure_ascii=False).lower()
    for needle in ("tbd", "todo:", "lorem ipsum", "placeholder", "fixme"):
        if needle in blob:
            return False, f"artifact contains placeholder marker {needle!r}"
    return True, ""


# ---------------------------------------------------------------------------
# Gate definition + driver
# ---------------------------------------------------------------------------


@dataclass
class GateDefinition:
    """Declarative phase gate (Spec §9 example).

    ``required``, ``required_glob`` and ``semantic_checks`` accept both the
    terse legacy form (strings / path dicts) and the Hardening v1.1 form
    (dicts with ``schema``, ``aggregate_as``, ``source``).
    """

    name: str
    required: list[Any] = field(default_factory=list)
    required_glob: list[Any] = field(default_factory=list)
    semantic_checks: list[Any] = field(default_factory=list)
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


def _norm_required(entry: Any) -> dict[str, Any]:
    if isinstance(entry, str):
        return {"path": entry}
    return dict(entry)


def _norm_glob(entry: Any) -> dict[str, Any]:
    if isinstance(entry, str):
        return {"pattern": entry}
    return dict(entry)


def _norm_semantic(entry: Any) -> dict[str, Any]:
    if isinstance(entry, str):
        return {"check": entry, "source": None}
    return {"check": entry.get("check"), "source": entry.get("source")}


class GateRunner:
    """Apply a GateDefinition to a set of on-disk artifacts."""

    def __init__(self, *, workdir: os.PathLike[str] | str = ".") -> None:
        self.workdir = Path(workdir).resolve()

    def _abs(self, path: str) -> str:
        return path if os.path.isabs(path) else str(self.workdir / path)

    def _validate_schema(self, result: GateResult, payload: Any, schema_name: str, label: str) -> None:
        schema = load_schema_or_none(schema_name)
        if schema is None:
            # v1.1.1: fail closed. A gate that *declares* a schema is asserting
            # the artifact is machine-checkable; if the schema itself cannot be
            # loaded we have no contract to enforce, and silently skipping would
            # turn every declared schema into an advisory one. That is the same
            # class of bug as `phase complete` trusting the agent's word.
            result.add_failure(
                "schema", label,
                f"schema {schema_name!r} is declared but could not be loaded; "
                f"cannot validate {label}",
            )
            return
        errors = validate_instance(payload, schema)
        if errors:
            result.add_failure("schema", label, f"{schema_name}: " + "; ".join(str(e) for e in errors[:4]))

    def run(self, gate: GateDefinition, *, semantic_data: Optional[Mapping[str, Any]] = None,
            ctx: Optional[dict[str, Any]] = None) -> GateResult:
        """Execute *gate*.

        ``semantic_data`` may pre-seed sources (e.g. in-memory state); declared
        sources are still loaded from disk and take precedence.
        """
        ctx = dict(ctx or {})
        sources: dict[str, Any] = dict(semantic_data or {})
        result = GateResult(name=gate.name, passed=True)

        # 1. required files: existence → size → parse → schema
        for raw in gate.required:
            req = _norm_required(raw)
            path = req.get("path")
            if not path:
                result.add_failure("required.path", None, "required entry missing 'path'")
                continue
            abs_path = self._abs(path)
            min_bytes = int(req.get("min_bytes", 1))
            max_bytes = int(req.get("max_bytes", 50 * 1024 * 1024))
            ok, msg = check_exists(abs_path)
            if not ok:
                result.add_failure("existence", path, msg)
                continue
            ok, msg = check_max_size(abs_path, max_bytes)
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
                sources[path] = data
                items_key = req.get("items_key")
                items_schema = req.get("items_schema")
                if items_schema:
                    items = data.get(items_key) if items_key and isinstance(data, Mapping) else data
                    if not isinstance(items, list):
                        result.add_failure(
                            "schema", path,
                            f"items_schema {items_schema!r} declared but "
                            f"{items_key or '<root>'!r} is not an array",
                        )
                    else:
                        schema = load_schema_or_none(items_schema)
                        if schema is None:
                            # v1.1.1: fail closed (see _validate_schema).
                            result.add_failure(
                                "schema", path,
                                f"items_schema {items_schema!r} is declared but could not "
                                f"be loaded; cannot validate items of {path}",
                            )
                        else:
                            for i, item in enumerate(items):
                                errors = validate_instance(item, schema)
                                if errors:
                                    result.add_failure(
                                        "schema", path,
                                        f"{items_schema}[{i}]: " + "; ".join(str(e) for e in errors[:3]),
                                    )
            schema_name = req.get("schema")
            if schema_name and path in sources:
                self._validate_schema(result, sources[path], schema_name, path)

        # 2. glob artifacts: match → parse → aggregate → schema
        for raw in gate.required_glob:
            spec = _norm_glob(raw)
            pattern = spec.get("pattern")
            if not pattern:
                result.add_failure("required_glob", None, "required_glob entry missing 'pattern'")
                continue
            min_matches = int(spec.get("min_matches", 1))
            ok, msg, matches = check_glob_matches(str(self.workdir / pattern), min_matches=min_matches)
            if not ok:
                result.add_failure("required_glob", pattern, msg)
                continue
            result.add_note(f"glob {pattern} matched {len(matches)} file(s)")

            if spec.get("parse_json"):
                parsed: list[Any] = []
                parse_failed = False
                for match in matches:
                    rel = os.path.relpath(match, self.workdir)
                    ok_i, msg_i, data_i = check_json_parseable(match)
                    if not ok_i:
                        result.add_failure("glob_parseability", rel, msg_i)
                        parse_failed = True
                        continue
                    schema_name = spec.get("schema")
                    if schema_name:
                        self._validate_schema(result, data_i, schema_name, rel)
                    parsed.append(data_i)
                if parse_failed:
                    continue
                aggregate_as = spec.get("aggregate_as")
                if aggregate_as:
                    sources[aggregate_as] = {aggregate_as: parsed}
                    result.add_note(f"aggregated {len(parsed)} file(s) into {aggregate_as!r}")
                else:
                    sources[pattern] = parsed

        # 3. semantic checks — each bound to its declared source (v1.1 §3)
        for raw in gate.semantic_checks:
            spec = _norm_semantic(raw)
            check_name = spec.get("check")
            source = spec.get("source")
            if not check_name:
                result.add_failure("semantic", None, "semantic_checks entry missing 'check'")
                continue
            if check_name not in SEMANTIC_CHECKS:
                result.add_failure("semantic", None, f"unknown semantic check: {check_name!r}")
                continue

            if source is not None:
                if source not in sources:
                    result.add_failure(
                        "semantic", source,
                        f"semantic check {check_name!r} declares source {source!r} "
                        f"but no such artifact was loaded",
                    )
                    continue
                ok, msg = run_semantic(check_name, sources[source], ctx)
                if not ok:
                    result.add_failure("semantic", source, f"{check_name}: {msg}")
                continue

            # Legacy form: no source declared. Try each loaded source and pass
            # if any accepts. New gate definitions should always declare one.
            passed = False
            detail = "no sources loaded"
            for src_path, src_data in sources.items():
                if not isinstance(src_data, Mapping):
                    continue
                ok, msg = run_semantic(check_name, src_data, ctx)
                if ok:
                    passed = True
                    break
                detail = f"{src_path}: {msg}"
            if not passed:
                result.add_failure("semantic", None, f"{check_name} failed for all sources ({detail})")
            else:
                result.add_note(f"semantic {check_name} passed via unbound source lookup (legacy form)")

        return result


# Built-in gate library — defaults for the standard mini-audit phases.
#
# Hardening v1.1: every semantic check names its artifact, glob artifacts are
# parsed and aggregated, and artifacts with a shipped schema declare it.
DEFAULT_PHASE_GATES: dict[str, dict[str, Any]] = {
    "L1": {
        "name": "L1",
        "required": [
            {"path": "mini-audit/attack-surface/intent-corpus.json", "parse_json": True},
        ],
        "semantic_checks": [
            {"check": "non_empty", "source": "mini-audit/attack-surface/intent-corpus.json"},
        ],
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
        "required_glob": [
            {"pattern": "mini-audit/probe-workspace/*/probe-summary.md", "min_matches": 1},
        ],
    },
    "L6": {
        "name": "L6",
        "required_glob": [
            {
                "pattern": "mini-audit/chamber-workspace/*/debate.json",
                "parse_json": True,
                "aggregate_as": "chambers",
            },
        ],
        "semantic_checks": [
            {"check": "every_chamber_closed", "source": "chambers"},
            {"check": "every_valid_candidate_has_boundary_sentence", "source": "chambers"},
        ],
    },
    "L6b": {
        "name": "L6b",
        "required_glob": [
            {"pattern": "mini-audit/findings-draft/*/draft.md", "min_matches": 1},
        ],
    },
    "L6c": {
        "name": "L6c",
        "required_glob": [
            {"pattern": "mini-audit/findings/*/poc.sh", "min_matches": 1},
            {"pattern": "mini-audit/findings/*/evidence/exploit.log", "min_matches": 1},
        ],
    },
    "L7": {
        "name": "L7",
        "required": [
            {
                "path": "mini-audit/findings.json",
                "parse_json": True,
                "items_key": "findings",
                "items_schema": "finding",
            },
            {"path": "mini-audit/final-audit-report.md", "min_bytes": 100},
            {"path": "mini-audit/coverage-ledger.json", "parse_json": True, "schema": "coverage-ledger"},
            {"path": "mini-audit/audit-state.json", "parse_json": True, "schema": "audit-state"},
        ],
        "semantic_checks": [
            {"check": "every_confirmed_has_verifier", "source": "mini-audit/findings.json"},
            {"check": "coverage_no_planned", "source": "mini-audit/coverage-ledger.json"},
            {"check": "audit_state_terminal_phases", "source": "mini-audit/audit-state.json"},
        ],
    },
    # ------------------------------------------------------------------
    # v1.1.1 §19 — gate coverage beyond balanced.
    #
    # Before v1.1.1 only balanced (L1–L7) declared gates, so `lite`, `deep`,
    # `confirm`, `judge`, `longshot` and `knowledge-base` phases advanced on
    # the agent's word alone — the exact failure mode §2 removed for balanced.
    # The gates below cover every phase that the SKILL documents as writing a
    # *dedicated* artifact file. Phases whose output is a section of a shared
    # document (L2/L3/L4-style: P4–P7, P11) or that have no documented artifact
    # contract (diff/revisit/merge/reinvest) are intentionally left ungated;
    # see the "Gate coverage" table in SKILL.md for the rationale.
    # ------------------------------------------------------------------
    "Q0": {
        "name": "Q0",
        "required": [
            {"path": "mini-audit/attack-surface/recon-report.md", "min_bytes": 100},
            {"path": "mini-audit/attack-surface/candidates-summary.md", "min_bytes": 1},
            {"path": "mini-audit/attack-surface/candidates.jsonl", "min_bytes": 1},
        ],
    },
    "Q1": {
        "name": "Q1",
        "required": [
            {"path": "mini-audit/attack-surface/lite-q1-summary.md", "min_bytes": 1},
        ],
    },
    "Q2": {
        "name": "Q2",
        "required": [
            {"path": "mini-audit/attack-surface/lite-q2-summary.md", "min_bytes": 1},
            {"path": "mini-audit/attack-surface/unauthenticated-surface.md", "min_bytes": 1},
        ],
    },
    "Q3": {
        "name": "Q3",
        "required": [
            {"path": "mini-audit/attack-surface/lite-consolidation-manifest.json", "parse_json": True},
        ],
    },
    "Q4": {
        "name": "Q4",
        "required": [
            {"path": "mini-audit/attack-surface/lite-verification-summary.md", "min_bytes": 1},
        ],
    },
    "P1": {
        "name": "P1",
        "required": [
            {"path": "mini-audit/attack-surface/advisories.md", "min_bytes": 1},
        ],
    },
    "P1.5": {
        "name": "P1.5",
        "required": [
            {"path": "mini-audit/attack-surface/env-provisioning.md", "min_bytes": 1},
        ],
    },
    "P2": {
        "name": "P2",
        "required": [
            {"path": "mini-audit/attack-surface/intent-corpus.json", "parse_json": True},
        ],
        "semantic_checks": [
            {"check": "non_empty", "source": "mini-audit/attack-surface/intent-corpus.json"},
        ],
    },
    "P3": {
        "name": "P3",
        "required": [
            {"path": "mini-audit/attack-surface/knowledge-base-report.md", "min_bytes": 100},
        ],
    },
    "P8": {
        "name": "P8",
        "required_glob": [
            {"pattern": "mini-audit/probe-workspace/*/probe-summary.md", "min_matches": 1},
        ],
    },
    "P9": {
        "name": "P9",
        "required": [
            {"path": "mini-audit/attack-surface/spec-gap.md", "min_bytes": 1},
        ],
    },
    "P10": {
        "name": "P10",
        "required_glob": [
            {
                "pattern": "mini-audit/chamber-workspace/*/debate.json",
                "parse_json": True,
                "aggregate_as": "chambers",
            },
        ],
        "semantic_checks": [
            {"check": "every_chamber_closed", "source": "chambers"},
            {"check": "every_valid_candidate_has_boundary_sentence", "source": "chambers"},
        ],
    },
    "P12": {
        "name": "P12",
        "required": [
            {"path": "mini-audit/attack-surface/variant-candidates.md", "min_bytes": 1},
        ],
    },
    "P13": {
        "name": "P13",
        "required_glob": [
            {"pattern": "mini-audit/findings/*/poc.*", "min_matches": 1},
        ],
    },
    "P14": {
        "name": "P14",
        "required_glob": [
            {"pattern": "mini-audit/findings/*/report.md", "min_matches": 1},
        ],
    },
    "P15": {
        "name": "P15",
        "required": [
            {"path": "mini-audit/final-audit-report.md", "min_bytes": 100},
        ],
    },
    "P16": {
        "name": "P16",
        "required_glob": [
            {"pattern": "mini-audit/findings/*/patch-bypass.md", "min_matches": 1},
        ],
    },
    "P17": {
        "name": "P17",
        "required": [
            {"path": "mini-audit/attack-surface/cleanup-manifest.json", "parse_json": True},
        ],
    },
    "V1": {
        "name": "V1",
        "required": [
            {"path": "mini-audit/confirm-workspace/findings-inventory.json", "parse_json": True},
        ],
    },
    "V7": {
        "name": "V7",
        "required": [
            {"path": "mini-audit/confirmation-report.md", "min_bytes": 100},
        ],
    },
    "J1": {
        "name": "J1",
        "required_glob": [
            {"pattern": "mini-audit/findings/*/judge-verdict.md", "min_matches": 1},
        ],
    },
    "J2": {
        "name": "J2",
        "required": [
            {"path": "mini-audit/judge-report.md", "min_bytes": 100},
        ],
    },
    "X3": {
        "name": "X3",
        "required": [
            {"path": "mini-audit/longshot/longshot-summary.md", "min_bytes": 1},
        ],
    },
    "X1": {
        "name": "X1",
        "required": [
            {"path": "mini-audit/longshot/targets.json", "parse_json": True},
        ],
    },
    "X2": {
        "name": "X2",
        "required_glob": [
            {"pattern": "mini-audit/longshot/findings-draft/longshot-*.md", "min_matches": 1},
        ],
    },
    "R0": {
        "name": "R0",
        "required": [
            {"path": "mini-audit/attack-surface/intent-corpus.json", "parse_json": True},
        ],
        "semantic_checks": [
            {"check": "non_empty", "source": "mini-audit/attack-surface/intent-corpus.json"},
        ],
    },
    "I2": {
        "name": "I2",
        "required_glob": [
            {"pattern": "mini-audit/findings/*/wave-*-verdict.md", "min_matches": 1},
        ],
    },
    "K1": {
        "name": "K1",
        "required": [
            {"path": "mini-audit/attack-surface/sbom.json", "parse_json": True},
        ],
    },
    "K2": {
        "name": "K2",
        "required": [
            {"path": "mini-audit/attack-surface/knowledge-base-report.md", "min_bytes": 100},
            {"path": "mini-audit/attack-surface/unauthenticated-surface.md", "min_bytes": 1},
        ],
    },
}


#: Canonical phase → mode map (SKILL §"Phase catalog"). Used by
#: :func:`gated_phases` / :func:`ungated_phases` and by the docs check so the
#: "every persisted phase is gated" claim stays verifiable.
MODE_PHASES: dict[str, tuple[str, ...]] = {
    "lite": ("Q0", "Q1", "Q2", "Q3", "Q4"),
    "balanced": ("L1", "L2", "L3", "L4", "L5", "L6", "L6b", "L6c", "L7"),
    "deep": (
        "P1", "P1.5", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9",
        "P10", "P11", "P12", "P13", "P14", "P15", "P16", "P17",
    ),
    "confirm": ("V1", "V1.5", "V2", "V3", "V4", "V5", "V6", "V7"),
    "revisit": ("R0", "R5", "R7", "R8", "R9", "R10", "R10k", "R11", "R11b", "R11c"),
    "merge": ("M1", "M2", "M3", "M4", "M5", "M6", "M7"),
    "longshot": ("X1", "X2", "X3"),
    "reinvest": ("I1", "I2", "I3"),
    "knowledge-base": ("KB0", "K1", "K2"),
    "judge": ("J1", "J2"),
}


def gate_for(phase: str) -> GateDefinition:
    if phase not in DEFAULT_PHASE_GATES:
        raise GateError(f"no default gate defined for phase {phase!r}")
    return GateDefinition.from_dict(DEFAULT_PHASE_GATES[phase])


def has_gate(phase: str) -> bool:
    return phase in DEFAULT_PHASE_GATES


def gated_phases(mode: Optional[str] = None) -> list[str]:
    """Return the gated phases, optionally restricted to one *mode*."""
    if mode is None:
        return sorted(DEFAULT_PHASE_GATES)
    return [p for p in MODE_PHASES.get(mode, ()) if p in DEFAULT_PHASE_GATES]


def ungated_phases(mode: str) -> list[str]:
    """Return phases declared by *mode* that have no deterministic gate.

    v1.1.1 §19: these are deliberate — they either write into a shared
    document (no dedicated artifact) or have no artifact contract at all.
    The list exists so the gap is *named* rather than silently assumed away.
    """
    return [p for p in MODE_PHASES.get(mode, ()) if p not in DEFAULT_PHASE_GATES]
