"""snapshot — one-stop read-only view of the audit's current state (spec §7).

The snapshot is a derived artifact. It SELECTs, JOINs, DERIVEs, and SUMMARIZEs
from the canonical state already on disk — objective, ledger, attack graph,
coverage ledger, candidate store, diff-scope (if any), search-saturation (if
any), and the audit-state machine. It writes *no* canonical state.

Spec §7 contract:

    Runtime may organize facts for the model, but must not evaluate which fact
    deserves action.

The snapshot deliberately exposes a model-friendly overview: "reopenable blocked
paths", "open P0 questions", "high-chain-potential candidates", "coverage debt",
"broken chains", "recent relevant changes", "remaining budget". These are *facts
the runtime can compute*. Anything that requires picking which fact matters
most — ranking, planning, choosing, recommending next action — is explicitly
out of scope and lives in the Skill layer.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Optional

from . import attack_graph as graph_mod
from . import objective as objective_mod
from . import research_state as research_mod
from .atomic_io import read_json_or_corrupt
from .search_saturation import VERDICT_FLOOR_MET


SNAPSHOT_VERSION = 1


def _read_optional(path: Path) -> Optional[dict[str, Any]]:
    if not path.exists():
        return None
    try:
        data = read_json_or_corrupt(path)
    except Exception:
        return None
    return data if isinstance(data, dict) else None


def _by_kind(ledger: Mapping[str, Any], kind: str) -> list[dict[str, Any]]:
    """Look up a list-typed section on the ledger by either singular or plural
    kind (e.g. ``blocked_path`` or ``blocked_paths``)."""
    if not isinstance(ledger, Mapping):
        return []
    for candidate in (kind, f"{kind}s"):
        if candidate in ledger:
            items = ledger.get(candidate)
            return [item for item in (items or []) if isinstance(item, Mapping)]
    return []


def _reopenable_blocked_paths(ledger: Mapping[str, Any]) -> list[dict[str, Any]]:
    """A blocked path is reopenable right now iff its blocker assumption is
    already ``disproved``. The runtime is allowed to derive this — the
    *decision* to reopen is a model concern; this just lists what would
    actually reopen if asked.
    """
    blocked_paths = _by_kind(ledger, "blocked_path")
    referenced_refs = {
        (p.get("blocker") or {}).get("assumption_ref")
        for p in blocked_paths
    }
    referenced_refs.discard(None)
    assumptions_by_id = {
        a.get("id"): a for a in _by_kind(ledger, "assumption")
        if a.get("id") in referenced_refs
    }
    out = []
    for path in blocked_paths:
        if path.get("status") != "blocked":
            continue
        ref = (path.get("blocker") or {}).get("assumption_ref")
        if not ref:
            continue
        assumption = assumptions_by_id.get(ref)
        if assumption is None:
            continue
        if assumption.get("status") == "disproved":
            out.append({
                "blocked_path": path.get("id"),
                "candidate_id": path.get("candidate_id"),
                "blocker_type": (path.get("blocker") or {}).get("type"),
                "blocker_claim": (path.get("blocker") or {}).get("claim"),
                "reopened_by": {"assumption_id": assumption.get("id"),
                                 "assumption_key": assumption.get("key")},
            })
    return out


def _open_p0_questions(ledger: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [q for q in _by_kind(ledger, "open_question")
            if q.get("priority") == "P0"
            and q.get("status") not in ("resolved", "refuted", "deferred")]


def _high_chain_potential_candidates(
    candidate_store: Mapping[str, tuple[Any, dict[str, Any], dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Candidates whose declared ``research.chain_potential == high``.

    ``candidate_store`` is the ``candidate_id -> (path, payload, record)``
    index from :func:`runtime.research_state.candidate_store`. The runtime
    only filters; the decision to investigate them is a model concern.
    """
    out: list[dict[str, Any]] = []
    for _cid, (_path, _payload, record) in candidate_store.items():
        if not isinstance(record, Mapping):
            continue
        block = record.get("research") or {}
        if block.get("chain_potential") != "high":
            continue
        out.append({
            "candidate_id": record.get("candidate_id"),
            "status": record.get("status"),
            "chain_potential": block.get("chain_potential"),
            "requires_capabilities": block.get("requires_capabilities") or [],
            "grants_capabilities": block.get("grants_capabilities") or [],
            "blocked_by": block.get("blocked_by") or [],
        })
    return out


def _coverage_debt(coverage: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if coverage is None:
        return {
            "coverage_ledger_present": False,
            "planning_status": None,
            "units_planned_or_in_progress": 0,
            "units_covered": 0,
            "units_total": 0,
        }
    units = coverage.get("units") or []
    planned = sum(1 for u in units
                  if isinstance(u, Mapping)
                  and u.get("status") in ("planned", "in_progress"))
    covered = sum(1 for u in units
                  if isinstance(u, Mapping) and u.get("status") == "covered")
    return {
        "coverage_ledger_present": True,
        "planning_status": coverage.get("planning_status"),
        "units_planned_or_in_progress": planned,
        "units_covered": covered,
        "units_total": len(units),
    }


def _broken_chains(graph: Optional[Mapping[str, Any]],
                   findings: Optional[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Confirmed findings whose capability chain is broken on the graph.

    A "broken chain" is mechanical: the finding's
    ``boundary.capability_refs`` either are missing or do not form a
    verified path on the attack graph (per
    :func:`runtime.search_closure.evaluate_finding_closure`). The model
    reads the list and decides whether to re-investigate; the runtime
    does not pick which finding to act on.
    """
    if graph is None or findings is None:
        return []
    from . import search_closure as closure_mod

    rows: list[dict[str, Any]] = []
    for finding in findings.get("findings") or []:
        if not isinstance(finding, Mapping):
            continue
        if finding.get("verdict") != "confirmed":
            continue
        result = closure_mod.evaluate_finding_closure(
            finding, graph, {}, base_dir=None,
        )
        if not result.closed:
            rows.append({
                "finding_id": finding.get("id"),
                "slug": finding.get("slug"),
                "missing": list(result.failures),
            })
    return rows


def _verified_capabilities(graph: Optional[Mapping[str, Any]]) -> list[str]:
    if graph is None:
        return []
    nodes = graph.get("nodes") or [] if isinstance(graph, Mapping) else []
    return [str(n.get("key")) for n in nodes
            if isinstance(n, Mapping)
            and n.get("type") == "capability"
            and n.get("status") == graph_mod.TRAVERSABLE_STATUS]


def _recent_relevant_changes(diff_scope: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if diff_scope is None:
        return {"diff_scope_present": False}
    return {
        "diff_scope_present": True,
        "scope_type": diff_scope.get("scope_type"),
        "selector": diff_scope.get("selector"),
        "merge_base": diff_scope.get("merge_base"),
        "baseline": diff_scope.get("baseline"),
        "target": diff_scope.get("target"),
        "changed_files_count": len(diff_scope.get("changed") or []),
    }


def _remaining_budget(state: Optional[Mapping[str, Any]]) -> dict[str, Any]:
    if state is None or not isinstance(state, Mapping):
        return {
            "phases_completed": 0,
            "phases_in_progress": 0,
            "phases_failed": 0,
            "phases_total": 0,
        }
    phases = state.get("phases") or {}
    if not isinstance(phases, Mapping):
        return {
            "phases_completed": 0,
            "phases_in_progress": 0,
            "phases_failed": 0,
            "phases_total": 0,
        }
    counts: dict[str, int] = {"completed": 0, "in_progress": 0,
                              "failed": 0, "skipped": 0, "pending": 0}
    for entry in phases.values():
        if not isinstance(entry, Mapping):
            continue
        status = str(entry.get("status") or "pending")
        counts[status] = counts.get(status, 0) + 1
    return {
        "phases_completed": counts["completed"],
        "phases_in_progress": counts["in_progress"],
        "phases_failed": counts["failed"],
        "phases_skipped": counts["skipped"],
        "phases_total": sum(counts.values()),
    }


def build_snapshot(audit_root: os.PathLike[str] | str,
                   *,
                   findings: Optional[Mapping[str, Any]] = None,
                   include_recent_changes: bool = True) -> dict[str, Any]:
    """Aggregate every observable the model needs in one read.

    The snapshot is a plain dict — callers may serialize it to JSON. The
    function performs *no* ranking, planning, choosing, recommending, or
    state mutation. It only SELECTs / JOINs / DERIVEs / SUMMARIZEs (spec §7).
    """
    audit_root = Path(audit_root)
    objective = objective_mod.load_objective(audit_root) if (audit_root / "audit-objective.json").exists() else None
    ledger_doc = research_mod.load_research_state(audit_root)
    ledger = ledger_doc.get("ledger") if isinstance(ledger_doc, Mapping) else None
    graph = ledger_doc.get("graph") if isinstance(ledger_doc, Mapping) else None
    coverage = _read_optional(audit_root / "coverage-ledger.json")
    diff_scope = _read_optional(audit_root / "diff-scope.json")
    saturation = _read_optional(audit_root / "search-saturation.json")
    state = _read_optional(audit_root / "audit-state.json")
    candidate_index = research_mod.candidate_store(audit_root)
    findings = _read_optional(audit_root / "findings.json")

    summary = graph_mod.graph_summary(graph) if isinstance(graph, Mapping) else {}

    if isinstance(graph, Mapping):
        frontier_open = graph_mod.blocked_frontier(graph)
        goal_set = set(graph_mod.goal_nodes(graph))
        reachable_set = set(graph_mod.verified_reachable(graph))
        reachable_goals = [g for g in goal_set if g in reachable_set]
    else:
        frontier_open = []
        goal_set = set()
        reachable_set = set()
        reachable_goals = []

    snapshot: dict[str, Any] = {
        "schema_version": SNAPSHOT_VERSION,
        "audit_id": (objective or {}).get("audit_id"),
        "kind": "derived.snapshot",
        "objective": {
            "path": str(audit_root / "audit-objective.json"),
            "summary": objective_mod.content_hash(objective) if objective else None,
            "principal": (objective or {}).get("principal"),
            "target_capabilities": (objective or {}).get("target_capabilities"),
        },
        "verified_capabilities": _verified_capabilities(graph),
        "frontier": {
            "open": frontier_open,
            "reachable_goals": reachable_goals,
            "total_goals": list(goal_set),
        },
        "reopenable_blocked_paths": _reopenable_blocked_paths(ledger) if isinstance(ledger, Mapping) else [],
        "open_p0_questions": _open_p0_questions(ledger) if isinstance(ledger, Mapping) else [],
        "high_chain_potential_candidates": _high_chain_potential_candidates(candidate_index),
        "coverage_debt": _coverage_debt(coverage),
        "broken_chains": _broken_chains(graph if isinstance(graph, Mapping) else None,
                                          findings if isinstance(findings, Mapping) else None),
        "saturation_floor": saturation.get("verdict", {}).get("value") if saturation else None,
        "saturation_floor_met": (
            saturation.get("verdict", {}).get("value") == VERDICT_FLOOR_MET
            if saturation else False
        ),
        "remaining_budget": _remaining_budget(state),
    }
    if include_recent_changes:
        snapshot["recent_relevant_changes"] = _recent_relevant_changes(diff_scope)
    return snapshot


def write_snapshot(audit_root: os.PathLike[str] | str,
                   *,
                   out: Optional[os.PathLike[str] | str] = None) -> dict[str, Any]:
    """Build and write the snapshot. Read-only with respect to canonical state;
    the only file written is ``mini-audit/snapshot.json`` (or ``out`` if given)."""
    from .atomic_io import write_json_atomic
    snapshot = build_snapshot(audit_root)
    target = Path(out) if out else Path(audit_root) / "snapshot.json"
    write_json_atomic(target, snapshot)
    return snapshot
