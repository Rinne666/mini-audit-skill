"""Search saturation — is the search finished, or merely out of budget? (§16-§17).

The trap this module exists to avoid is defining "done" as "the agent says it
is done". A saturation rule that accepts ``status: deferred`` is a rule the
agent can satisfy by relabelling, which hands the completion gate straight back
to the thing being gated.

So there are exactly two hard conditions, and both are mechanically checkable:

* **coverage** — planning complete, units planned, none still planned or in
  progress;
* **P0 open questions** — none may remain ``open``, and every terminal state
  must carry evidence: a resolution needs a reason and at least one reference
  that resolves to a real file, and a deferral needs a reason, a reopen
  condition, and either an attempted investigation or a blocker that is still
  standing.

Everything else — how many high-chain candidates remain, how many assumptions
are unverified, whether the goals are reachable — is reported and does not
block. Those numbers are debt, and debt belongs in a report a human reads, not
in a gate that a relabelled field can pass.

Terminology matters here. A passing gate means *the minimum completion
conditions were met under the current budget*, never "the search is exhausted".
The report says so in as many words, because the failure mode of a saturation
report is being quoted as a guarantee.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from . import attack_graph as graph_mod
from . import research_state as research
from .atomic_io import write_json_atomic
from .objective import utc_now
from .search_lock import search_governance_lock


SATURATION_FILENAME = "search-saturation.json"

#: The verdict namespace this module writes under. Spec §4 (Skill-First Refactor v2)
#: requires runtime-generated semantic fields to live in ``derived.*`` /
#: ``system.*`` / ``validation.*`` namespaces; saturation checks are *derived
#: facts about the floor*, never verdicts on whether the audit should stop. The
#: value is left as a state name (``floor_met`` / ``floor_not_met``) for
#: machine consumption; whether to stop the audit is a model decision the
#: runtime does not originate.
VERDICT_KIND = "derived.saturation_check"
VERDICT_FLOOR_MET = "floor_met"
VERDICT_FLOOR_NOT_MET = "floor_not_met"
VERDICT_MINIMUM_MET = "search_saturated_under_current_budget"  # legacy label
VERDICT_BLOCKED = "hard_gate_failed"  # legacy label

#: Terminal states a P0 open question may be closed with.
P0_TERMINAL = ("resolved", "refuted", "deferred")


def _resolve(base_dir: Optional[Path], ref: str) -> bool:
    """Does a reference resolve to a file? ``path:line`` is accepted."""
    if base_dir is None:
        return False
    text = str(ref).strip()
    if not text:
        return False
    head, sep, tail = text.rpartition(":")
    attempts = [text] + ([head] if sep and tail.isdigit() else [])
    for attempt in attempts:
        path = Path(attempt)
        resolved = path if path.is_absolute() else base_dir / path
        if resolved.exists():
            return True
    return False


def _blocker_still_standing(ledger: Mapping[str, Any], path_id: str,
                            failures: list[str]) -> bool:
    """A deferral may lean on a blocker only while that blocker still holds."""
    path = research.find_by_id(ledger, "blocked_path", path_id)
    if path is None:
        failures.append(f"deferred P0 question cites {path_id}, which is no blocked path")
        return False
    if path.get("status") != "blocked":
        failures.append(
            f"deferred P0 question cites {path_id}, whose status is "
            f"{path.get('status')!r} — a reopened or closed path is actionable, "
            "not a reason to wait"
        )
        return False
    ref = (path.get("blocker") or {}).get("assumption_ref")
    if not ref:
        return True
    assumption = research.find_by_id(ledger, "assumption", str(ref))
    if assumption is None:
        failures.append(f"{path_id} depends on assumption {ref}, which does not exist")
        return False
    if assumption.get("status") != "supported":
        failures.append(
            f"{path_id} depends on assumption {ref}, whose status is "
            f"{assumption.get('status')!r}, not 'supported' — the blocker is not "
            "established, so it cannot justify deferring"
        )
        return False
    return True


def _coverage_result(coverage: Optional[Mapping[str, Any]]) -> tuple[bool, int, list[str]]:
    """Reuse the gate's own coverage predicate rather than restating it.

    Imported locally: ``gates`` imports this module for its L7 check, so a
    module-level import here would be a cycle. Restating the rule instead would
    be worse — two definitions of "coverage is complete" that can drift is
    exactly what ``schema.py`` exists to avoid.
    """
    from .gates import run_semantic

    if coverage is None:
        return False, 0, ["coverage-ledger.json is missing"]
    ok, message = run_semantic("coverage_no_planned", coverage)
    unresolved = 0
    for unit in coverage.get("units", []) or []:
        if isinstance(unit, Mapping) and unit.get("status") in ("planned", "in_progress"):
            unresolved += 1
    return ok, unresolved, ([] if ok else [message])


def _candidate_settled(record: Mapping[str, Any]) -> bool:
    """A high-chain candidate is settled once something happened to it.

    Promoted, rejected, refuted, or blocked-with-a-reason all count. Still
    sitting there with a hypothesis is the only unsettled state.
    """
    block = record.get("research")
    block = block if isinstance(block, Mapping) else {}
    if record.get("status") in ("rejected", "promoted"):
        return True
    if block.get("local_validity") == "refuted":
        return True
    return bool(block.get("blocked_by"))


def evaluate(
    *,
    ledger: Optional[Mapping[str, Any]],
    graph: Optional[Mapping[str, Any]],
    coverage: Optional[Mapping[str, Any]],
    candidates: Mapping[str, Any],
    base_dir: Optional[os.PathLike[str] | str] = None,
) -> dict[str, Any]:
    """Compute the hard gate and the soft signals. Pure — no writes."""
    base = Path(base_dir).resolve() if base_dir is not None else None
    failures: list[str] = []

    coverage_ok, coverage_unresolved, coverage_messages = _coverage_result(coverage)
    failures.extend(coverage_messages)

    questions = research.iter_objects(ledger, "open_question") if ledger else []
    p0_questions = [q for q in questions if q.get("priority") == "P0"]
    p0_open = [q for q in p0_questions if q.get("status") not in P0_TERMINAL]
    for question in sorted(p0_open, key=lambda q: str(q.get("id"))):
        failures.append(
            f"P0 open question {question.get('id')} is {question.get('status')!r}; "
            f"terminal states are {list(P0_TERMINAL)}"
        )

    for question in sorted(p0_questions, key=lambda q: str(q.get("id"))):
        status = question.get("status")
        ident = question.get("id")
        if status in ("resolved", "refuted"):
            if not str(question.get("reason") or "").strip():
                failures.append(f"P0 question {ident} is {status} with no reason")
            refs = [str(r) for r in question.get("evidence_refs") or []]
            if not refs:
                failures.append(f"P0 question {ident} is {status} with no evidence_refs")
            for ref in refs:
                if not _resolve(base, ref):
                    failures.append(
                        f"P0 question {ident} cites evidence {ref!r}, which resolves "
                        "to no file"
                    )
        elif status == "deferred":
            if not str(question.get("reason") or "").strip():
                failures.append(f"deferred P0 question {ident} has no reason")
            if not (question.get("reopen_if") or []):
                failures.append(
                    f"deferred P0 question {ident} has no reopen_if; a deferral "
                    "without a condition to come back on is an abandonment"
                )
            attempts = [str(r) for r in question.get("attempt_refs") or []]
            blocker_ref = str(question.get("blocked_path_ref") or "")
            if not attempts and not blocker_ref:
                failures.append(
                    f"deferred P0 question {ident} shows neither attempt_refs nor a "
                    "blocked_path_ref; nothing records that it was investigated"
                )
            for ref in attempts:
                if not _resolve(base, ref):
                    failures.append(
                        f"deferred P0 question {ident} cites attempt {ref!r}, which "
                        "resolves to no file"
                    )
            if blocker_ref and ledger is not None:
                _blocker_still_standing(ledger, blocker_ref, failures)

    reachable_goals: list[str] = []
    frontier_edges = 0
    if graph is not None:
        reachable_goals = [g["goal"] for g in graph_mod.paths_to_goals(graph)["reachable_goals"]]
        frontier_edges = len(graph_mod.blocked_frontier(graph))

    blocked_paths = research.iter_objects(ledger, "blocked_path") if ledger else []
    assumptions = research.iter_objects(ledger, "assumption") if ledger else []
    edges = list(graph.get("edges", [])) if graph else []
    nodes = list(graph.get("nodes", [])) if graph else []
    high_chain_open = [
        cid for cid, (_path, _payload, record) in sorted(candidates.items())
        if isinstance(record, Mapping)
        and (record.get("research") or {}).get("chain_potential") == "high"
        and not _candidate_settled(record)
    ]

    def p0_by_status(status: str) -> int:
        return sum(1 for q in p0_questions if q.get("status") == status)

    signals: dict[str, Any] = {
        "p0_resolved": p0_by_status("resolved"),
        "p0_refuted": p0_by_status("refuted"),
        "p0_deferred": p0_by_status("deferred"),
        "p0_open": len(p0_open),
        "p1_open": sum(1 for q in questions
                       if q.get("status") not in P0_TERMINAL and q.get("priority") == "P1"),
        "p2_open": sum(1 for q in questions
                       if q.get("status") not in P0_TERMINAL and q.get("priority") == "P2"),
        "high_chain_candidates_open": len(high_chain_open),
        "blocked_paths": sum(1 for p in blocked_paths if p.get("status") == "blocked"),
        "high_priority_blocked_paths": sum(
            1 for p in blocked_paths
            if p.get("status") == "blocked" and p.get("priority") == "high"
        ),
        "reopened_paths": sum(1 for p in blocked_paths if p.get("status") == "reopened"),
        "unverified_assumptions": sum(
            1 for a in assumptions if a.get("status") == "unverified"
        ),
        "proposed_edges": sum(1 for e in edges
                              if isinstance(e, Mapping) and e.get("status") == "proposed"),
        "blocked_edges": sum(1 for e in edges
                             if isinstance(e, Mapping) and e.get("status") == "blocked"),
        "verified_capabilities": sum(
            1 for n in nodes if isinstance(n, Mapping)
            and n.get("type") == "capability"
            and n.get("status") == graph_mod.TRAVERSABLE_STATUS
        ),
        "reachable_goals": len(reachable_goals),
        "goals": len(graph_mod.goal_nodes(graph)) if graph else 0,
        "frontier_edges": frontier_edges,
    }

    hard_gate = {
        "passed": not failures,
        "coverage_unresolved": coverage_unresolved,
        "p0_open": len(p0_open),
        "failures": failures,
    }
    return {
        "schema_version": 1,
        "generated_at": utc_now(),
        "generation": ledger.get("generation") if ledger else None,
        "hard_gate": hard_gate,
        "signals": signals,
        "debt": {
            "summary": (
                f"{signals['p0_deferred']} deferred / {signals['p0_resolved']} resolved "
                f"P0 questions; {signals['high_chain_candidates_open']} high-chain "
                f"candidate(s) still open"
            ),
            "p0_deferred": signals["p0_deferred"],
            "p0_resolved": signals["p0_resolved"],
        },
        "verdict": {
            "kind": VERDICT_KIND,
            "value": VERDICT_FLOOR_MET if not failures else VERDICT_FLOOR_NOT_MET,
            # Legacy label kept for any consumer still reading the bare string.
            "legacy_label": VERDICT_MINIMUM_MET if not failures else VERDICT_BLOCKED,
        },
        "verdict_means": (
            "runtime reports the saturation floor as a derived fact; whether to "
            "stop the audit is a model decision the runtime does not originate. "
            "A passing floor means the minimum completion conditions were met "
            "under the current budget — a floor, not a claim that the search "
            "is at its ceiling."
        ),
    }


def report(audit_root: os.PathLike[str] | str,
           *, workdir: Optional[os.PathLike[str] | str] = None) -> dict[str, Any]:
    """Evaluate and write ``mini-audit/search-saturation.json``.

    The report is a derived artifact, not research state: reading happens under
    the shared lock (so the ledger and graph are one snapshot), the write does
    not need it.
    """
    from . import objective as objective_mod

    audit_root = Path(audit_root)
    workdir_path = Path(workdir or ".").resolve()
    with search_governance_lock(audit_root, exclusive=False, operation="search saturation"):
        state = research.load_research_state(audit_root)
        objective = objective_mod.load_objective(audit_root)
        coverage = _read_optional(audit_root / "coverage-ledger.json")
    document = evaluate(
        ledger=state.get("ledger"),
        graph=state.get("graph"),
        coverage=coverage,
        candidates=research.candidate_store(audit_root),
        base_dir=workdir_path,
    )
    document["search_governance_enabled"] = bool(state.get("exists") and objective is not None)
    write_json_atomic(audit_root / SATURATION_FILENAME, document)
    return document


def _read_optional(path: Path) -> Optional[dict[str, Any]]:
    from .atomic_io import read_json_or_corrupt

    if not path.exists():
        return None
    try:
        data = read_json_or_corrupt(path)
    except Exception:
        return None
    return data if isinstance(data, dict) else None
