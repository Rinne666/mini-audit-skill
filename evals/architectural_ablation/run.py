"""Architectural ablation runner (spec §14, structural-mode).

The full spec §14 mandates an 8-variant E2E ablation run with a real
model. Building 7 additional fixtures + spinning up a model harness
is out of scope for this commit; what we *do* ship is the **structural
mode** of the same ablation:

* The runner takes the existing `evals/long_horizon/chain-001/scenario.json`
  fixture (a single canonical case).
* For each registered ablation (A..G), the runner rewrites the scenario's
  deltas to simulate the *absence* of an architecture component.
* The rewritten scenario is replayed through the same `evals/long_horizon_run.py`
  code path so the four metrics on the four scenarios are computed
  consistently.
* Results are reported as a table; per-row deltas show how each
  architectural component contributes to (or removes) a metric.

A *real* Model E2E ablation (the model-runs-each-variant-and-compares-
outcomes variant from spec §14) remains a future extension; this
script pins the *direction* (which metric moves when which component
is removed) so a future contributor can build the model harness
without re-deriving the structural assumptions.

Available ablations (matching spec §14):

  A  no attack graph         — remove every related.capabilities /
                              capability_consumer / edge reference
                              from the deltas; the runtime cannot
                              reason across nodes.
  B  no search ledger         — drop facts_add / assumptions_add from
                              the deltas; the agent reasons in a
                              vacuum.
  C  no blocked-path retention — assume nothing stays across rounds;
                              the agent cannot reopen a path.
  D  no review chamber        — collapse 4-role chamber into a single
                              synthesiser pass; lose adversarial
                              coverage.
  E  no independent verifier  — drop the cold-verifier step; findings
                              ship on chamber confidence only.
  F  no search governance     — skip the open_questions / research_intents
                              bookkeeping; the agent picks next steps
                              without an audit trail.
  G  no decision provenance   — strip decision_id from any delta;
                              find audit compliance regression.

The four metrics are reused from `evals/long_horizon_run.py`:

  premature_rejection_rate
  blocked_path_reopen_rate
  chain_completion_recall
  (the 4th, saturation-floor compliance, is reported by a sibling
   scenario; this runner reports the three above)

Usage:

    python evals/architectural_ablation/run.py [--ablate A]
                                               [--ablate B ...]
                                               [--keep DIR]

A "no change" baseline run with no --ablate flag is supported so the
output is interpretable side-by-side with the committed numbers.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILL_ROOT = HERE.parent.parent.parent
EVALS_ROOT = HERE.parent.parent
if str(EVALS_ROOT) not in sys.path:
    sys.path.insert(0, str(EVALS_ROOT))
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from evals import long_horizon_run as lh  # noqa: E402

SCENARIO_ID = "CHAIN-001"   # the long_horizon/chain-001 scenario
                            # reuses long_horizon_run's loader; the
                            # runner accepts any id the loader knows.

METRIC_NAMES = ("premature_rejection_rate",
                "blocked_path_reopen_rate",
                "chain_completion_recall")


def _strip_attack_graph(scenario: dict) -> dict:
    """A: no attack graph — remove every related.capabilities /
    capability_consumer / edge reference from the deltas. The runtime
    cannot reason across nodes; chain extension becomes unreachable."""
    rewritten = copy.deepcopy(dict(scenario))
    for step in rewritten.get("steps") or []:
        delta = step.get("delta") or {}
        delta.pop("edges_add", None)
        delta.pop("edges_update", None)
        for cap in delta.get("capabilities_add") or []:
            cap.pop("requires_capabilities", None)
            cap.pop("grants_capabilities", None)
        for op_key in ("facts_add", "assumptions_add"):
            for entry in delta.get(op_key) or []:
                entry.pop("source_refs", None)
    return rewritten


def _strip_search_ledger(scenario: dict) -> dict:
    """B: no search ledger — drop facts_add / assumptions_add.
    The agent reasons in a vacuum. Blocked paths that reference
    assumptions are also dropped to keep the replay consistent
    (the runtime refuses dangling references)."""
    rewritten = copy.deepcopy(dict(scenario))
    for step in rewritten.get("steps") or []:
        delta = step.get("delta") or {}
        delta.pop("facts_add", None)
        delta.pop("assumptions_add", None)
        # Drop blocked_path entries whose blocker names an assumption
        # — without assumptions the reference is unresolvable.
        delta["blocked_paths_add"] = [
            bp for bp in (delta.get("blocked_paths_add") or [])
            if not ((bp.get("blocker") or {}).get("assumption_ref"))
        ]
        delta["blocked_paths_reopen"] = []
        # Drop assumption-update / question updates that target the
        # removed ledger kinds.
        delta["assumptions_update"] = []
        delta["questions_resolve"] = []
    return rewritten


def _strip_blocked_path_retention(scenario: dict) -> dict:
    """C: no blocked-path retention — block every added blocked_path
    from being reopened. The audit cannot recover when a prior blocker
    is overturned."""
    rewritten = copy.deepcopy(dict(scenario))
    for step in rewritten.get("steps") or []:
        delta = step.get("delta") or {}
        # Pin every newly added blocked path to status='blocked' even
        # when the agent submits a status='reopened' update — the
        # retention layer is removed.
        for bp in delta.get("blocked_paths_add") or []:
            bp["status"] = "blocked"
        delta["blocked_paths_reopen"] = []
    return rewritten


def _collapse_chamber(scenario: dict) -> dict:
    """D: no review chamber — drop the ideator / devils-advocate / tracer
    rounds. Keep only the synthesiser (one round, no adversarial)."""
    rewritten = copy.deepcopy(dict(scenario))
    rewritten.setdefault("meta", {})["chamber_rounds"] = 1
    rewritten["meta"]["chamber_roles"] = ["synthesiser"]
    return rewritten


def _strip_cold_verifier(scenario: dict) -> dict:
    """E: no independent verifier — drop the cold-verify step.
    Findings ship on chamber confidence only."""
    rewritten = copy.deepcopy(dict(scenario))
    rewritten.setdefault("meta", {})["cold_verify"] = False
    return rewritten


def _strip_search_governance(scenario: dict) -> dict:
    """F: no search governance — skip the open_questions /
    research_intents bookkeeping. The agent picks next steps
    without an audit trail."""
    rewritten = copy.deepcopy(dict(scenario))
    for step in rewritten.get("steps") or []:
        delta = step.get("delta") or {}
        delta.pop("research_intents_add", None)
        delta.pop("research_intents_update", None)
        delta.pop("intents_add", None)
        delta.pop("questions_add", None)
        delta.pop("questions_resolve", None)
    return rewritten


def _strip_decision_provenance(scenario: dict) -> dict:
    """G: no decision provenance — strip decision_id from any delta;
    audit compliance regression. The runtime canonicaliser refuses
    such deltas; we mark the scenario as expected-to-fail rather than
    letting it crash."""
    rewritten = copy.deepcopy(dict(scenario))
    for step in rewritten.get("steps") or []:
        delta = step.get("delta") or {}
        for entry in delta.get("decisions") or []:
            entry.pop("decision_id", None)
            entry["decided_by"] = ""
            entry["reason"] = ""
    rewritten.setdefault("meta", {})["expect_failure"] = "decision_provenance"
    return rewritten


ABLATIONS: dict[str, callable] = {
    "A": _strip_attack_graph,
    "B": _strip_search_ledger,
    "C": _strip_blocked_path_retention,
    "D": _collapse_chamber,
    "E": _strip_cold_verifier,
    "F": _strip_search_governance,
    "G": _strip_decision_provenance,
}


def run_one(scenario_id: str, ablation: str | None,
            keep: Path | None) -> dict:
    scenarios = lh.load_scenarios(only=[scenario_id])
    if not scenarios:
        raise RuntimeError(f"scenario {scenario_id!r} not found")
    scenario = scenarios[0]

    if keep:
        workdir_base = keep / scenario_id
        workdir_base.mkdir(parents=True, exist_ok=True)
        import shutil
        baseline_dir = workdir_base / "baseline"
        ablated_dir = workdir_base / f"abl_{ablation or 'none'}"
        for path in (baseline_dir, ablated_dir):
            if ablation is None and path is ablated_dir:
                continue
            shutil.rmtree(path, ignore_errors=True)
        baseline_dir.mkdir(parents=True, exist_ok=True)
    else:
        baseline_dir = Path(tempfile.mkdtemp(prefix="ablation-baseline-"))

    baseline = lh.evaluate_scenario(scenario, baseline_dir)
    baseline_metrics = baseline["metrics"]

    if ablation is None:
        return {"id": scenario_id, "ablation": None,
                "baseline": baseline_metrics, "ablated": None,
                "delta": None, "counts": baseline["counts"]}

    if ablation not in ABLATIONS:
        raise RuntimeError(
            f"unknown ablation {ablation!r}; available: {sorted(ABLATIONS)}"
        )
    rewritten = ABLATIONS[ablation](scenario)
    if keep:
        ablated_dir.mkdir(parents=True, exist_ok=True)
    else:
        ablated_dir = Path(tempfile.mkdtemp(prefix="ablation-abl-"))
    ablated = lh.evaluate_scenario(rewritten, ablated_dir)
    ablated_metrics = ablated["metrics"]

    delta = {}
    for name in METRIC_NAMES:
        delta[name] = round(ablated_metrics.get(name, 0.0)
                            - baseline_metrics.get(name, 0.0), 4)
    return {"id": scenario_id, "ablation": ablation,
            "baseline": baseline_metrics, "ablated": ablated_metrics,
            "delta": delta, "counts": ablated["counts"]}


def render_table(reports: list[dict]) -> str:
    header = ["metric", "baseline"] + [r["ablation"] or "none"
                                       for r in reports]
    out = [" | ".join(header)]
    out.append("-" * len(out[0]))
    for metric in METRIC_NAMES:
        row = [metric, f"{reports[0]['baseline'].get(metric, 0.0):.4f}"]
        for r in reports[1:]:
            d = r["delta"].get(metric, 0.0)
            row.append(f"{d:+.4f}")
        out.append(" | ".join(row))
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="architectural_ablation.run")
    p.add_argument("--ablate", action="append",
                   choices=sorted(ABLATIONS) + [None],
                   help="ablation letter (A..G); repeat to chain multiple")
    p.add_argument("--scenario", default="CHAIN-001",
                   help="scenario id (default CHAIN-001; the runner reuses "
                        "long_horizon_run's loader so any id it knows will work)")
    p.add_argument("--keep", type=Path, default=None,
                   help="keep the worktrees under DIR for inspection")
    args = p.parse_args(argv)

    reports: list[dict] = []
    if not args.ablate:
        args.ablate = [None]
    for ablation in args.ablate:
        reports.append(run_one(args.scenario, ablation, args.keep))

    print(json.dumps(reports, indent=2))
    if len(reports) > 1:
        print()
        print(render_table(reports))
    return 0


if __name__ == "__main__":
    sys.exit(main())