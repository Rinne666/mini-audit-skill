"""Long-horizon replay evaluator (Search Governance v1, Phase E0 — §19-§22).

What this measures
------------------
The runtime's handling of long-lived research state. Each scenario is a
scripted sequence of research deltas — the material an agent would have
submitted across several rounds — replayed against a real audit root. The
question is whether the runtime:

* keeps a locally valid but currently unreachable primitive instead of losing
  it (``premature_rejection_rate``);
* reopens a blocked path when the assumption its blocker rested on is
  disproved (``blocked_path_reopen_rate``);
* ends with the whole capability chain verified-reachable
  (``chain_completion_recall``).

What this does **not** measure
------------------------------
Whether Search Governance finds more vulnerabilities. Nothing here runs a
model, and no scenario compares "with governor" against "without". Claiming a
discovery-rate improvement from these numbers would be claiming that a state
machine made an analyst smarter. §22 says so explicitly.

A note on the simulated verdict
-------------------------------
A scenario's oracle says which candidates *should* survive. Deciding that a
candidate was rejected needs a policy, and the policy here is deliberately
stated in terms of research state the **runtime** maintains:

    keep a candidate iff a blocker of its is still standing, or a capability it
    requires (or grants) is now reachable, or it has been promoted

Every clause reads the ledger and graph, not the scenario file. So a runtime
that loses a blocked path, or fails to reopen one, or never connects the chain,
will reject a candidate the oracle expected to survive — which is what makes
the metric a test of the runtime rather than of this script. The clause is a
stand-in for the Review Chamber, which is where this judgement lives in a real
audit.

Fixture layout
--------------
Each fixture is a directory, not a file::

    evals/long_horizon/<fixture>/
        A.py  B.py  C.py     real sources — one third of the chain each
        scenario.json        objective, candidates, delta sequence, oracle, thresholds

The sources are real because the deltas cite ``file:line`` evidence, and
``_assert_evidence_resolves`` checks every such reference resolves to a real
line before anything is replayed. A fixture that drifted from its sources would
otherwise still pass, demonstrating the chain against nothing.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

HERE = Path(__file__).resolve().parent
SKILL_ROOT = HERE.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from runtime import attack_graph as graph_mod  # noqa: E402
from runtime import objective as objective_mod  # noqa: E402
from runtime import research_state as rs  # noqa: E402


SCENARIO_DIR = HERE / "long_horizon"
SCHEMA_VERSION = 1

METRIC_NAMES = (
    "premature_rejection_rate",
    "blocked_path_reopen_rate",
    "chain_completion_recall",
)


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


class ScenarioError(RuntimeError):
    """A scenario could not be replayed."""


def load_scenarios(directory: Path = SCENARIO_DIR,
                   only: Optional[Sequence[str]] = None) -> list[dict[str, Any]]:
    """Load every ``<fixture>/scenario.json`` under *directory*.

    A scenario is a directory, not a file, because its sources have to be real:
    the deltas cite file:line evidence, and a fixture whose "code" is an inline
    string can only ever be checked against itself. The fixture directory is
    attached as ``_fixture_dir`` so the replay can copy those sources in.
    """
    scenarios = []
    for path in sorted(Path(directory).glob("*/scenario.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if only and document.get("id") not in only:
            continue
        document["_fixture_dir"] = str(path.parent)
        scenarios.append(document)
    return scenarios


def _copy_sources(scenario: Mapping[str, Any], workdir: Path) -> list[Path]:
    """Copy the fixture's real sources into the replay root.

    Without this the evidence references in the deltas would point at files that
    do not exist, and the replay would be validating a story rather than a
    fixture.
    """
    fixture_dir = Path(scenario.get("_fixture_dir") or ".")
    sources = list(scenario.get("sources") or [])
    if not sources:
        raise ScenarioError(
            f"scenario {scenario.get('id')!r} declares no sources; its deltas "
            "cite file:line evidence, so the fixture must ship the files it cites"
        )
    copied: list[Path] = []
    for relative in sources:
        origin = fixture_dir / relative
        if not origin.is_file():
            raise ScenarioError(
                f"scenario {scenario.get('id')!r} declares source {relative!r}, "
                f"which does not exist in {fixture_dir}"
            )
        target = workdir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(origin.read_text(encoding="utf-8"), encoding="utf-8")
        copied.append(target)
    return copied


#: ``path:line`` — the form the deltas use. Anything else is treated as opaque,
#: so a delta may still cite an agent artifact without this check guessing.
_FILE_LINE = re.compile(r"^([^:]+):(\d+)$")


def _assert_evidence_resolves(scenario: Mapping[str, Any], workdir: Path) -> int:
    """Every ``file:line`` reference must hit a real line in the replay root.

    The line number is part of the claim: "B.py builds the SQL by concatenation"
    is true of one line and false of the file as a whole. A fixture that drifts
    away from its sources — an edited source, a stale line number — would still
    replay cleanly, and the chain would be demonstrated against nothing.
    """
    checked = 0
    for index, step in enumerate(scenario.get("steps") or []):
        for operation, entries in (step.get("delta") or {}).items():
            if operation == "schema_version" or not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                for field in ("evidence_refs", "verification_refs", "source_refs"):
                    for ref in entry.get(field) or []:
                        match = _FILE_LINE.match(str(ref))
                        if not match:
                            continue
                        relative, line = match.group(1), int(match.group(2))
                        path = workdir / relative
                        if not path.is_file():
                            raise ScenarioError(
                                f"step {index} ({operation}.{field}) cites {ref}, "
                                f"but {relative} is not in the replay root"
                            )
                        total = len(path.read_text(encoding="utf-8").splitlines())
                        if line < 1 or line > total:
                            raise ScenarioError(
                                f"step {index} ({operation}.{field}) cites {ref}, "
                                f"but {relative} has only {total} lines"
                            )
                        checked += 1
    if not checked:
        raise ScenarioError(
            f"scenario {scenario.get('id')!r} ships sources but cites no file:line "
            "reference; the check would pass without verifying anything"
        )
    return checked


def replay(scenario: Mapping[str, Any], workdir: Path) -> dict[str, Any]:
    """Rebuild one scenario from scratch and return the resulting state."""
    audit_root = workdir / "mini-audit"
    audit_root.mkdir(parents=True, exist_ok=True)

    _copy_sources(scenario, workdir)
    evidence_checked = _assert_evidence_resolves(scenario, workdir)

    objective_mod.init_and_bootstrap(audit_root, scenario["objective"], agent="long-horizon")

    candidates_path = audit_root / "candidates" / "review-chamber-candidates.json"
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    candidates_path.write_text(
        json.dumps({"source": "review-chamber", "candidates": scenario["candidates"]}),
        encoding="utf-8")

    applied: list[dict[str, Any]] = []
    for index, step in enumerate(scenario["steps"]):
        report = rs.apply_delta(audit_root, step["delta"],
                                agent=step["delta"].get("agent_id", f"step-{index}"))
        applied.append({"step": index, "note": step.get("note", ""),
                        "created": report["created"], "warnings": report["warnings"]})

    return {"audit_root": audit_root, "workdir": workdir, "steps": applied,
            "evidence_refs_checked": evidence_checked}


# ---------------------------------------------------------------------------
# The simulated chamber verdict
# ---------------------------------------------------------------------------


def _reachable_names(graph: Mapping[str, Any]) -> set[str]:
    reachable = graph_mod.verified_reachable(graph)
    names = set()
    for node_id in reachable:
        node = graph_mod.find_node_by_id(graph, node_id)
        if node is not None and node.get("name"):
            names.add(str(node["name"]))
    return names


def _recorded_blocker(ledger: Mapping[str, Any], candidate_id: str) -> bool:
    """Is a blocked path the runtime's recorded reason to keep this lead?

    The blocker does **not** have to be established for the lead to be worth
    keeping — that is the entire point of "blocked, not rejected". Requiring
    its assumption to be ``supported`` would reject exactly the candidates the
    mechanism exists to preserve, and would make the metric agree with the
    failure it is supposed to detect.
    """
    for path in rs.iter_objects(ledger, "blocked_path"):
        if path.get("candidate_id") == candidate_id and path.get("status") == "blocked":
            return True
    return False


def _kept_by_research_state(record: Mapping[str, Any], ledger: Mapping[str, Any],
                            graph: Mapping[str, Any]) -> bool:
    """See the module docstring: every clause reads runtime-maintained state.

    A lead is kept when either a capability it needs (or gains) is now held, or
    a blocked path records why it cannot be used yet. Neither clause consults
    the scenario, so a runtime that drops the blocker, fails to reopen it, or
    never connects the chain will lose the lead and move the metric.
    """
    research_block = record.get("research") or {}
    node_names = _reachable_names(graph)
    for field in ("requires_capabilities", "grants_capabilities"):
        for name in research_block.get(field) or []:
            if str(name) in node_names:
                return True
    return _recorded_blocker(ledger, str(record.get("candidate_id")))


def apply_simulated_verdict(audit_root: Path, ledger: Mapping[str, Any],
                            graph: Mapping[str, Any]) -> list[str]:
    """Record the simulated verdict, and return the candidates it rejected."""
    path = audit_root / "candidates" / "review-chamber-candidates.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    rejected: list[str] = []
    for record in payload.get("candidates", []):
        if record.get("status") in ("promoted", "rejected"):
            continue
        if _kept_by_research_state(record, ledger, graph):
            continue
        record["status"] = "rejected"
        rejected.append(str(record.get("candidate_id")))
    path.write_text(json.dumps(payload), encoding="utf-8")
    return rejected


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def evaluate_scenario(scenario: Mapping[str, Any], workdir: Path) -> dict[str, Any]:
    state = replay(scenario, workdir)
    audit_root = state["audit_root"]
    ledger = rs.load_ledger(audit_root) or {}
    graph = graph_mod.load_graph(audit_root) or {}

    rejected = apply_simulated_verdict(audit_root, ledger, graph)
    oracle = scenario.get("oracle") or {}

    retain = list(oracle.get("retain") or [])
    premature = sorted(set(retain) & set(rejected))

    should_reopen = list(oracle.get("should_reopen") or [])
    reopened: list[str] = []
    for path_id in should_reopen:
        path = rs.find_by_id(ledger, "blocked_path", str(path_id))
        if path is not None and path.get("status") == "reopened":
            reopened.append(str(path_id))

    reachable = graph_mod.verified_reachable(graph)
    reachable_names = _reachable_names(graph)
    reachable_goals = {entry["goal"] for entry in graph_mod.paths_to_goals(graph)["reachable_goals"]}
    completed: list[dict[str, Any]] = []
    for chain in oracle.get("chains") or []:
        via_ok = all(str(name) in reachable_names for name in chain.get("via") or [])
        to_ok = any(
            graph_mod.find_node_by_id(graph, goal) is not None
            and str((graph_mod.find_node_by_id(graph, goal) or {}).get("name")) == str(chain.get("to"))
            for goal in reachable_goals
        )
        completed.append({"chain": chain, "complete": via_ok and to_ok})

    return {
        "id": scenario.get("id"),
        "name": scenario.get("name"),
        "counts": {
            "retain_total": len(retain),
            "prematurely_rejected": len(premature),
            "should_reopen_total": len(should_reopen),
            "reopened": len(reopened),
            "chains_total": len(completed),
            "chains_completed": sum(1 for c in completed if c["complete"]),
        },
        "detail": {
            "retain": retain,
            "prematurely_rejected": premature,
            "rejected_by_verdict": rejected,
            "should_reopen": should_reopen,
            "reopened": reopened,
            "chains": completed,
            "reachable": sorted(reachable),
        },
        "metrics": {
            "premature_rejection_rate": (
                len(premature) / len(retain) if retain else 0.0
            ),
            "blocked_path_reopen_rate": (
                len(reopened) / len(should_reopen) if should_reopen else 1.0
            ),
            "chain_completion_recall": (
                sum(1 for c in completed if c["complete"]) / len(completed) if completed else 1.0
            ),
        },
        "thresholds": dict(scenario.get("thresholds") or {}),
        "steps": state["steps"],
        # Surfaced, not just enforced: a check whose result nobody can see is a
        # check that can quietly stop running.
        "fixture": {
            "sources": list(scenario.get("sources") or []),
            "evidence_refs_checked": state["evidence_refs_checked"],
        },
    }


def aggregate(results: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    totals = {
        "retain_total": 0, "prematurely_rejected": 0,
        "should_reopen_total": 0, "reopened": 0,
        "chains_total": 0, "chains_completed": 0,
    }
    for result in results:
        for key in totals:
            totals[key] += int(result["counts"][key])
    return {
        "premature_rejection_rate": (
            totals["prematurely_rejected"] / totals["retain_total"]
            if totals["retain_total"] else 0.0
        ),
        "blocked_path_reopen_rate": (
            totals["reopened"] / totals["should_reopen_total"]
            if totals["should_reopen_total"] else 1.0
        ),
        "chain_completion_recall": (
            totals["chains_completed"] / totals["chains_total"]
            if totals["chains_total"] else 1.0
        ),
    }


def check_thresholds(results: Sequence[Mapping[str, Any]],
                     overall: Mapping[str, float]) -> list[str]:
    violations: list[str] = []
    for result in results:
        thresholds = result.get("thresholds") or {}
        for name in METRIC_NAMES:
            if name not in thresholds:
                continue
            actual = float(result["metrics"][name])
            required = float(thresholds[name])
            if actual < required:
                violations.append(
                    f"{result['id']}: {name} {actual:.4f} < required {required:.4f}"
                )
    return violations


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="long_horizon_run",
        description="Replay the long-horizon scenarios and report the three metrics",
    )
    parser.add_argument("--scenario", action="append", default=None,
                        help="only run the scenario with this id (repeatable)")
    parser.add_argument("--json", action="store_true", help="emit the full report as JSON")
    parser.add_argument("--keep", default=None,
                        help="replay into this directory instead of a temporary one")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    scenarios = load_scenarios(only=args.scenario)
    if not scenarios:
        print("no long-horizon scenarios found", file=sys.stderr)
        return 1

    results: list[dict[str, Any]] = []
    try:
        for scenario in scenarios:
            if args.keep:
                workdir = Path(args.keep) / str(scenario["id"])
                shutil.rmtree(workdir, ignore_errors=True)
                workdir.mkdir(parents=True, exist_ok=True)
                results.append(evaluate_scenario(scenario, workdir))
            else:
                with tempfile.TemporaryDirectory(prefix="long-horizon-") as tmp:
                    results.append(evaluate_scenario(scenario, Path(tmp)))
    except (rs.ResearchError, objective_mod.ObjectiveError, graph_mod.GraphError) as exc:
        print(f"replay failed: {exc}", file=sys.stderr)
        return 1

    overall = aggregate(results)
    violations = check_thresholds(results, overall)
    report = {
        "schema_version": SCHEMA_VERSION,
        "scenarios": results,
        "aggregate": overall,
        "violations": violations,
        "scope_note": (
            "these metrics describe the runtime's handling of long-lived research "
            "state, not vulnerability-discovery performance; no model was run and "
            "no with/without-governor comparison was made"
        ),
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for result in results:
            print(f"{result['id']}  {result['name']}")
            for name in METRIC_NAMES:
                print(f"    {name:28} {result['metrics'][name]:.4f}")
            print(f"    counts: {result['counts']}")
            fixture = result["fixture"]
            print(f"    fixture: {len(fixture['sources'])} source(s), "
                  f"{fixture['evidence_refs_checked']} evidence ref(s) resolved")
        print()
        for name in METRIC_NAMES:
            print(f"aggregate {name:28} {overall[name]:.4f}")
        if violations:
            print()
            for violation in violations:
                print(f"VIOLATION {violation}")
        else:
            print("\nall thresholds met")

    return 1 if violations else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
