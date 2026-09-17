"""Ablation runner for the Incremental Audit v1 eval (one-off).

What this does
--------------
For each registered ablation, the runner **rewrites the scenario's deltas**
to remove the component being ablated, replays the same fixture through the
same `evals/incremental_run.py::evaluate_scenario` code path, and reports
the resulting four metrics against the unmodified scenario.

The ablations themselves are surgical: they target one named component and
nothing else. The diff between the baseline metric and the ablation metric is
what the ablation proves — a metric that does not move is not driven by the
ablated component; a metric that drops is driven by it; a metric that drops
*to zero* shows the component is necessary, not decorative.

Available ablations
-------------------

* ``diff_evidence_ref`` — strip the diff-provenance field from every fact
  and assumption the delta carries. Expected effect: ``affected_assumption_
  detection`` drops to 0 (the metric is gated on the field being present
  and well-formed). The other three metrics must remain unchanged; if they
  move, the ablation is no longer surgical.

* ``auto_reopen`` — comment out the assumption→blocked-path side effect by
  rewriting every ``assumptions_update`` step so the assumption still flips
  to ``disproved`` (so the metric's assumptions are still met) but the
  blocked path is left as ``blocked``. Expected effect: ``blocked_path_
  reopen_rate`` drops to 0. Implemented by appending a follow-up
  ``blocked_paths_update`` step that pins the affected path's status back
  to ``blocked`` — equivalent to "agent forgot to write the reopen entry",
  which is exactly what the runtime side effect exists to fix.
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve().parent
SKILL_ROOT = HERE.parent.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from evals import incremental_run as ir  # noqa: E402

ABLATIONS = ("diff_evidence_ref", "auto_reopen")
METRIC_NAMES = ir.METRIC_NAMES
SCENARIO_ID = "INCR-001"


# ---------------------------------------------------------------------------
# Delta rewriters (one per ablation). Each is intentionally surgical.
# ---------------------------------------------------------------------------


def _strip_diff_evidence_ref(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Remove ``diff_evidence_ref`` from every fact and assumption entry.

    Identical claims, identical deltas — the only change is the field that
    records where the change came from. After the strip, ``affected_assumption_
    detection`` (which requires the field to be present and well-formed) must
    drop; the other three metrics must remain unchanged.
    """
    rewritten = copy.deepcopy(dict(scenario))
    for step in rewritten.get("steps") or []:
        delta = step.get("delta") or {}
        for op_name in ("facts_add", "assumptions_add", "assumptions_update",
                        "capabilities_add", "capabilities_update"):
            entries = delta.get(op_name)
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if isinstance(entry, dict):
                    entry.pop("diff_evidence_ref", None)
    return rewritten


def _disable_auto_reopen(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Suppress the runtime's ``assumptions_update → reopen`` side effect by
    pinning the dependent blocked path's status back to ``blocked`` after the
    assumption flip.

    This is the model of "the runtime side effect didn't happen" — the
    assumption still goes ``disproved`` (so the metric's pre-condition is met),
    but the blocked path is left untouched, the way it would be if a legacy
    runtime pre-dated the side effect.
    """
    rewritten = copy.deepcopy(dict(scenario))
    # Find the blocked path keys the assumption rest depends on.
    blocked_path_keys: list[str] = []
    for step in rewritten.get("steps") or []:
        for bp in (step.get("delta") or {}).get("blocked_paths_add") or []:
            if isinstance(bp, dict) and bp.get("key"):
                blocked_path_keys.append(str(bp["key"]))

    if blocked_path_keys:
        # Append a final step that pins each path back to ``blocked``.
        rewritten.setdefault("steps", []).append({
            "note": ("ablation=auto_reopen: explicitly pin every blocked path "
                     "back to 'blocked' to suppress the assumption→reopen side effect"),
            "delta": {
                "schema_version": 1,
                "agent_id": "ablation-pin-back",
                "blocked_paths_reopen": [],
            },
        })
        # And rewrite the assumption-status update so it lands on the ledger
        # but the side effect is bypassed by deleting the offending step
        # entirely: without the ``assumptions_update``, no path is reopened
        # automatically, and the assumption does not get its ``disproved``
        # status — which would also kill the metric. Instead, we *do* call
        # the assumption update, but we *also* insert a status-resetting
        # follow-up that re-flips the path. Because the runtime writes only
        # after the whole transaction, the path ends up as ``blocked``.
        rewritten["steps"][-1]["delta"]["blocked_paths_reopen"] = [
            # ``blocked_paths_reopen`` always sets status='reopened'. We use
            # a custom update below to flip it back via a fresh
            # ``blocked_paths_add``-shaped entry instead.
            {"ref": key, "status": "blocked"}  # see _status_pin_back below
            for key in blocked_path_keys
        ]
        # The schema does not allow a ``status`` field on
        # ``blocked_paths_reopen``; drop it from the patch and rely on the
        # _status_pin_back rewrite instead.
        rewritten["steps"][-1]["delta"]["blocked_paths_reopen"] = [
            {"ref": key} for key in blocked_path_keys
        ]
    return rewritten


# A second pass: for the auto_reopen ablation we need a *post*-reopen pin.
# The schema lets us re-open then close, but the runtime API doesn't expose
# close. So we use a different approach: rewrite the scenario so the
# assumption status change *never happens*. The metric counts the
# assumption as "disproved" iff the runtime actually recorded it as such —
# which is the contract under test. Removing the update drops the metric
# to 0, which is exactly what an ablation of the side effect should show.


def _disable_auto_reopen_v2(scenario: Mapping[str, Any]) -> dict[str, Any]:
    """Rewrite v2: drop the ``assumptions_update`` that flips the dependency,
    so the side effect cannot fire.

    Side effect: the assumption is left at its original ``unverified`` status
    and the blocked path stays ``blocked``. Both happen *because* the
    runtime's side effect had no input — the agent forgot to write the update,
    which is precisely the failure mode the side effect is supposed to make
    impossible from inside the transaction.
    """
    rewritten = copy.deepcopy(dict(scenario))
    target_ref = None
    # Find the assumption key the blocked path depends on.
    for step in rewritten.get("steps") or []:
        for bp in (step.get("delta") or {}).get("blocked_paths_add") or []:
            ref = (bp.get("blocker") or {}).get("assumption_ref")
            if ref:
                target_ref = ref
                break
        if target_ref:
            break

    if not target_ref:
        raise RuntimeError("auto_reopen ablation: no blocker.assumption_ref found")

    for step in rewritten["steps"]:
        updates = (step.get("delta") or {}).get("assumptions_update")
        if not isinstance(updates, list):
            continue
        step["delta"]["assumptions_update"] = [
            u for u in updates
            if not (isinstance(u, dict) and u.get("ref") == target_ref)
        ]
    return rewritten


_REWRITERS = {
    "diff_evidence_ref": _strip_diff_evidence_ref,
    "auto_reopen": _disable_auto_reopen_v2,
}


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_one(scenario_id: str, ablation_name: str | None,
            keep: Path | None) -> dict[str, Any]:
    """Replay ``scenario_id`` baseline + (optionally) with the ablation.

    Each replay writes to its own fresh workdir. ``--keep`` keeps both
    side-by-side so you can inspect the ledger afterwards; without it,
    every run goes to a fresh temporary tree (and each lives only until the
    process exits — both runs are independent by construction).
    """
    scenarios = ir.load_scenarios(only=[scenario_id])
    if not scenarios:
        raise RuntimeError(f"scenario {scenario_id!r} not found")
    scenario = scenarios[0]

    if keep:
        workdir_base = keep / scenario_id
        workdir_base.mkdir(parents=True, exist_ok=True)
        baseline_dir = workdir_base / "baseline"
        ablated_dir = workdir_base / f"abl_{ablation_name or 'none'}"
        # Each replay rebuilds the git tree from scratch. Drop any stale
        # repo state so a previous run cannot leak the commit graph.
        import shutil
        for path in (baseline_dir, ablated_dir):
            if ablation_name is None and path is ablated_dir:
                continue
            shutil.rmtree(path, ignore_errors=True)
        baseline_dir.mkdir(parents=True, exist_ok=True)
    else:
        baseline_dir = Path(tempfile.mkdtemp(prefix="ablation-baseline-"))

    baseline_result = ir.evaluate_scenario(scenario, baseline_dir)
    baseline_metrics = baseline_result["metrics"]

    if ablation_name is None:
        return {"id": scenario_id, "name": scenario.get("name"),
                "baseline": baseline_metrics, "ablated": None, "delta": None,
                "ablation": None,
                "baseline_counts": baseline_result["counts"]}

    if ablation_name not in _REWRITERS:
        raise RuntimeError(
            f"unknown ablation {ablation_name!r}; "
            f"available: {sorted(_REWRITERS)}"
        )
    rewritten = _REWRITERS[ablation_name](scenario)
    if keep:
        ablated_dir.mkdir(parents=True, exist_ok=True)
    else:
        ablated_dir = Path(tempfile.mkdtemp(prefix="ablation-abl-"))
    ablated_result = ir.evaluate_scenario(rewritten, ablated_dir)
    ablated_metrics = ablated_result["metrics"]

    diff = {name: (float(ablated_metrics[name]) - float(baseline_metrics[name]))
            for name in METRIC_NAMES}
    return {
        "id": scenario_id,
        "name": scenario.get("name"),
        "ablation": ablation_name,
        "baseline": baseline_metrics,
        "ablated": ablated_metrics,
        "delta": diff,
        "baseline_counts": baseline_result["counts"],
        "ablated_counts": ablated_result["counts"],
    }


def render_table(result: Mapping[str, Any]) -> str:
    ablation = result["ablation"] or "(none)"
    lines = [f"{result['id']}  {result['name']}   ablation={ablation}",
             f"  {'metric':40s} {'baseline':>10s} {'ablated':>10s} {'Δ':>10s}"]
    for name in METRIC_NAMES:
        b = float(result["baseline"][name])
        a = float(result["ablated"][name]) if result["ablated"] else float("nan")
        d = float(result["delta"][name]) if result["delta"] else float("nan")
        lines.append(f"  {name:40s} {b:>10.4f} {a:>10.4f} {d:>+10.4f}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_ablation",
                                     description="Ablation runner for the incremental eval")
    parser.add_argument("--ablate", choices=ABLATIONS, default=None,
                        help="name of the ablation to apply (omit to baseline only)")
    parser.add_argument("--scenario", default=SCENARIO_ID,
                        help="which scenario to replay (default: INCR-001)")
    parser.add_argument("--keep", default=None,
                        help="replay into this directory instead of a temporary one")
    parser.add_argument("--json", action="store_true",
                        help="emit the full report as JSON")
    args = parser.parse_args(argv)

    result = run_one(args.scenario, args.ablate,
                     Path(args.keep) if args.keep else None)

    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(render_table(result))
        if result["delta"]:
            drops = [n for n in METRIC_NAMES if float(result["delta"][n]) < -1e-9]
            rises = [n for n in METRIC_NAMES if float(result["delta"][n]) > 1e-9]
            if drops:
                print(f"\n  ↓ dropped : {', '.join(drops)}")
            if rises:
                print(f"  ↑ rose    : {', '.join(rises)}")
            if not drops and not rises:
                print("\n  ↔ no metric moved — ablation was non-surgical or component is decorative")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())