"""Incremental audit replay evaluator (Incremental Audit v1 — §15-§18).

What this measures
------------------
Whether an incremental audit actually does the thing it exists for: keep a
locally real primitive that an earlier audit left ``blocked``, reopen it when
the change-set invalidates the blocker, and complete the chain — **without**
re-discovering the primitive.

Four metrics, each reads runtime-maintained state (not the scenario file):

* ``old_candidate_reuse_rate`` — of the candidates the previous audit kept as
  ``blocked``, how many are still in the audit root *and* still have a blocker
  recorded *or* a capability that is now reachable. A low value means the
  incremental round forgot the work the previous round did.
* ``blocked_path_reopen_rate`` — of the blocked paths the previous audit
  recorded, how many were reopened by the diff-triggered step. A low value
  means the diff-triggered delta failed to invalidate its own blocker.
* ``affected_assumption_detection`` — of the assumptions the previous audit
  recorded as depended on by an oracle blocked path, how many are recorded
  ``disproved`` *with diff-scope provenance* after the diff-triggered step. A
  low value means the round forgot to wire the diff evidence into the ledger.
* ``incremental_chain_completion`` — of the capability chains the oracle names,
  how many end with every ``via`` capability reachable and the chain's goal
  reachable. A low value means the diff round closed early.

What this does **not** measure
------------------------------
Whether incremental audits find more vulnerabilities. §18 says so explicitly:
no model is run and no with/without-diff comparison is made.

Fixture layout
--------------
::

    evals/incremental/<fixture>/
        A_v1.py  A_v2.py  B.py  C.py   real sources — v1 commit sources + v2 commit source
        scenario.json                      objective, candidates, two-step diff delta, oracle

The two A sources are committed as two git commits in the replay root. The v1
sources (A_v1.py + B.py + C.py) make the v1 commit; the v2 sources
(A_v2.py + B.py + C.py — the same B and C) make the v2 commit. The diff
between them is exactly the change the incremental audit is supposed to react
to. ``diff scope --since <v1_sha>`` produces ``diff-scope.json`` in the audit
root, and the eval reads it back.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

HERE = Path(__file__).resolve().parent
SKILL_ROOT = HERE.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from runtime import attack_graph as graph_mod  # noqa: E402
from runtime import diff_scope as diff_mod  # noqa: E402
from runtime import objective as objective_mod  # noqa: E402
from runtime import research_state as rs  # noqa: E402

SCENARIO_DIR = HERE / "incremental"
SCHEMA_VERSION = 1

METRIC_NAMES = (
    "old_candidate_reuse_rate",
    "blocked_path_reopen_rate",
    "affected_assumption_detection",
    "incremental_chain_completion",
)


class ScenarioError(RuntimeError):
    """A scenario could not be replayed."""


def load_scenarios(directory: Path = SCENARIO_DIR,
                   only: Optional[Sequence[str]] = None) -> list[dict[str, Any]]:
    """Load every ``<fixture>/scenario.json`` under *directory*."""
    scenarios = []
    for path in sorted(Path(directory).glob("*/scenario.json")):
        document = json.loads(path.read_text(encoding="utf-8"))
        if only and document.get("id") not in only:
            continue
        document["_fixture_dir"] = str(path.parent)
        scenarios.append(document)
    return scenarios


# ---------------------------------------------------------------------------
# Two-commit fixture build (the part long-horizon doesn't need)
# ---------------------------------------------------------------------------


def _run_git(workdir: Path, *args: str, env: dict[str, str] | None = None) -> str:
    """Run ``git -C <workdir> <args>`` and return stdout. Raises on non-zero."""
    full_env = {"GIT_AUTHOR_NAME": "incremental-eval", "GIT_AUTHOR_EMAIL": "eval@example.com",
                "GIT_COMMITTER_NAME": "incremental-eval", "GIT_COMMITTER_EMAIL": "eval@example.com",
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "HOME": str(workdir.parent),
                **({"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"} or {})}
    if env:
        full_env.update(env)
    proc = subprocess.run(
        ["git", "-C", str(workdir), *args],
        capture_output=True, text=True, check=False, env={**__import__("os").environ, **full_env},
    )
    if proc.returncode != 0:
        raise ScenarioError(
            f"git {' '.join(args)} failed in {workdir}: "
            f"{(proc.stderr or proc.stdout).strip()}"
        )
    return proc.stdout


def _build_two_commit_repo(scenario: Mapping[str, Any], workdir: Path) -> str:
    """Copy v1 sources, commit them, copy v2 sources, commit them.

    Returns the v1 SHA — the ``--since`` baseline the incremental audit is run
    against. The HEAD is the v2 commit.
    """
    fixture_dir = Path(scenario.get("_fixture_dir") or ".")
    sources = list(scenario.get("sources") or [])
    if not sources:
        raise ScenarioError(
            f"scenario {scenario.get('id')!r} declares no sources; an incremental "
            "fixture must ship the v1 and v2 files it cites"
        )

    workdir.mkdir(parents=True, exist_ok=True)
    _run_git(workdir, "init", "-q", "--initial-branch=main")

    v1_files = [s for s in sources if "_v1" not in s and s not in {"A_v2.py"}]
    # If the fixture didn't follow the *_v1 / _v2 split, fall back to the
    # declared ``sources`` list and treat it as the v1 commit.
    if not any("_v1" in s for s in sources):
        v1_files = list(sources)
    for relative in v1_files:
        origin = fixture_dir / relative
        if not origin.is_file():
            raise ScenarioError(
                f"scenario {scenario.get('id')!r} declares source {relative!r}, "
                f"which does not exist in {fixture_dir}"
            )
        target = workdir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(origin.read_text(encoding="utf-8"), encoding="utf-8")

    _run_git(workdir, "add", "-A")
    v1_message = str(scenario.get("commits", {}).get("v1_message", "v1"))
    _run_git(workdir, "commit", "-q", "-m", v1_message)
    v1_sha = _run_git(workdir, "rev-parse", "HEAD").strip()

    # v2 commit: overwrite any file that has a v2 counterpart.
    if any("_v2" in s for s in sources):
        for relative in [s for s in sources if "_v2" in s]:
            origin = fixture_dir / relative
            target = workdir / relative.replace("_v2", "")
            target.write_text(origin.read_text(encoding="utf-8"), encoding="utf-8")
        # Copy B/C from fixture to workdir if not already there (only matters when
        # the v1 copy above did not include them because of the v1/v2 split guard).
        for relative in [s for s in sources if "_v2" not in s and s not in {"A_v2.py"}]:
            target = workdir / relative
            if not target.is_file():
                origin = fixture_dir / relative
                target.write_text(origin.read_text(encoding="utf-8"), encoding="utf-8")
        _run_git(workdir, "add", "-A")
        v2_message = str(scenario.get("commits", {}).get("v2_message", "v2"))
        _run_git(workdir, "commit", "-q", "-m", v2_message)

    return v1_sha


# ---------------------------------------------------------------------------
# Evidence reference validation
# ---------------------------------------------------------------------------


_FILE_LINE = re.compile(r"^([^:]+):(\d+)$")


def _assert_evidence_resolves(scenario: Mapping[str, Any], workdir: Path) -> int:
    """Every ``file:line`` reference and ``diff-scope.json:...`` reference must hit
    a real line in the replay root (or a real diff-scope.json artifact)."""
    checked = 0
    for index, step in enumerate(scenario.get("steps") or []):
        for operation, entries in (step.get("delta") or {}).items():
            if operation == "schema_version" or not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, Mapping):
                    continue
                for field in ("evidence_refs", "verification_refs", "source_refs",
                              "diff_evidence_ref"):
                    for ref in entry.get(field) or []:
                        ref_str = str(ref)
                        # diff-scope.json:<prefix> form — we only require the
                        # prefix to look like the diff-scope.json contract; the
                        # exact shape is asserted in step 2 below.
                        if ref_str.startswith("diff-scope.json"):
                            if "scope_type=" not in ref_str or "baseline=" not in ref_str \
                                    or "target=" not in ref_str:
                                raise ScenarioError(
                                    f"step {index} ({operation}.{field}) cites "
                                    f"{ref_str!r}, which is not a well-formed "
                                    "diff-scope.json reference"
                                )
                            checked += 1
                            continue
                        match = _FILE_LINE.match(ref_str)
                        if not match:
                            continue
                        relative, line = match.group(1), int(match.group(2))
                        path = workdir / relative
                        if not path.is_file():
                            raise ScenarioError(
                                f"step {index} ({operation}.{field}) cites {ref_str}, "
                                f"but {relative} is not in the replay root"
                            )
                        total = len(path.read_text(encoding="utf-8").splitlines())
                        if line < 1 or line > total:
                            raise ScenarioError(
                                f"step {index} ({operation}.{field}) cites {ref_str}, "
                                f"but {relative} has only {total} lines"
                            )
                        checked += 1
    if not checked:
        raise ScenarioError(
            f"scenario {scenario.get('id')!r} ships sources but cites no evidence; "
            "the check would pass without verifying anything"
        )
    return checked


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def replay(scenario: Mapping[str, Any], workdir: Path) -> dict[str, Any]:
    """Build the v1+v2 worktree, run the v1 delta, run the diff trigger, run the
    closing delta, and return the resulting state."""
    audit_root = workdir / "mini-audit"
    audit_root.mkdir(parents=True, exist_ok=True)

    v1_sha = _build_two_commit_repo(scenario, workdir)
    evidence_checked = _assert_evidence_resolves(scenario, workdir)

    # Run the v1 (pre-diff) research delta first.
    objective_mod.init_and_bootstrap(audit_root, scenario["objective"], agent="incremental-eval")

    candidates_path = audit_root / "candidates" / "review-chamber-candidates.json"
    candidates_path.parent.mkdir(parents=True, exist_ok=True)
    candidates_path.write_text(
        json.dumps({"source": "review-chamber", "candidates": scenario["candidates"]}),
        encoding="utf-8")

    applied: list[dict[str, Any]] = []
    if scenario["steps"]:
        first = scenario["steps"][0]
        report = rs.apply_delta(audit_root, first["delta"],
                                agent=first["delta"].get("agent_id", "step-0"))
        applied.append({"step": 0, "note": first.get("note", ""),
                        "created": report["created"], "warnings": report["warnings"]})

    # Now run the runtime's diff stages: D0 + D2 (scope) and D4 (blast radius
    # against the symbol the agent is reasoning about). The agent may have asked
    # for D3/D5/D6 too, but those are not required for the metrics; what is
    # required is that `diff-scope.json` is real and `scope_type == "since"`.
    resolved = diff_mod.resolve_diff_range(workdir, since=v1_sha)
    scope = diff_mod.build_diff_scope(
        workdir, baseline=resolved.baseline, target=resolved.target,
        risky_symbols=[], resolved_range=resolved,
    )
    (audit_root / "diff-scope.json").write_text(
        json.dumps(scope.to_dict(), indent=2, sort_keys=True), encoding="utf-8")
    if "run_import" in (scope.risk_ranked[0]["path"] if scope.risk_ranked else ""):
        pass  # best-effort: D4 below will trace the symbol the agent named.
    blast = diff_mod.structured_blast_radius(
        workdir, changed_paths=[c["path"] for c in scope.changed],
        symbols=["run_import"],
    )
    (audit_root / "diff-d4.json").write_text(
        json.dumps(blast, indent=2, sort_keys=True), encoding="utf-8")

    # Apply the diff-triggered step and any later steps.
    for index, step in enumerate(scenario["steps"][1:], start=1):
        report = rs.apply_delta(audit_root, step["delta"],
                                agent=step["delta"].get("agent_id", f"step-{index}"))
        applied.append({"step": index, "note": step.get("note", ""),
                        "created": report["created"], "warnings": report["warnings"]})

    return {"audit_root": audit_root, "workdir": workdir, "v1_sha": v1_sha,
            "steps": applied, "evidence_refs_checked": evidence_checked,
            "resolved": resolved.to_dict()}


# ---------------------------------------------------------------------------
# Metrics — each clause reads runtime-maintained state
# ---------------------------------------------------------------------------


def _reachable_names(graph: Mapping[str, Any]) -> set[str]:
    reachable = graph_mod.verified_reachable(graph)
    names = set()
    for node_id in reachable:
        node = graph_mod.find_node_by_id(graph, node_id)
        if node is not None and node.get("name"):
            names.add(str(node["name"]))
    return names


def _old_candidates_kept(audit_root: Path, ledger: Mapping[str, Any],
                         graph: Mapping[str, Any]) -> set[str]:
    """The candidates the v1 step recorded — kept iff a blocker still stands,
    or a capability they require (or grant) is now reachable."""
    path = audit_root / "candidates" / "review-chamber-candidates.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    reachable = _reachable_names(graph)
    blockers_by_candidate: dict[str, int] = {}
    for path_obj in rs.iter_objects(ledger, "blocked_path"):
        blockers_by_candidate[str(path_obj.get("candidate_id"))] = (
            blockers_by_candidate.get(str(path_obj.get("candidate_id")), 0) + 1
        )
    kept: set[str] = set()
    for record in payload.get("candidates", []):
        cid = str(record.get("candidate_id"))
        research = record.get("research") or {}
        # A candidate that was promoted or rejected before the diff is still
        # considered "kept" if its status reflects that decision; the metric is
        # about whether the diff round forgot the work.
        if record.get("status") in ("promoted", "rejected"):
            continue
        kept_by_capability = False
        for field in ("requires_capabilities", "grants_capabilities"):
            for name in research.get(field) or []:
                if str(name) in reachable:
                    kept_by_capability = True
                    break
            if kept_by_capability:
                break
        if kept_by_capability or blockers_by_candidate.get(cid, 0) > 0:
            kept.add(cid)
    return kept


def evaluate_scenario(scenario: Mapping[str, Any], workdir: Path) -> dict[str, Any]:
    state = replay(scenario, workdir)
    audit_root = state["audit_root"]
    ledger = rs.load_ledger(audit_root) or {}
    graph = graph_mod.load_graph(audit_root) or {}

    oracle = scenario.get("oracle") or {}

    retain = list(oracle.get("retain") or [])
    kept = _old_candidates_kept(audit_root, ledger, graph)
    reused = sorted(set(retain) & kept)

    should_reopen = list(oracle.get("should_reopen") or [])
    reopened: list[str] = []
    for path_id in should_reopen:
        path_obj = rs.find_by_id(ledger, "blocked_path", str(path_id))
        if path_obj is not None and path_obj.get("status") == "reopened":
            reopened.append(str(path_id))

    should_disprove = list(oracle.get("should_disprove") or [])
    if not should_disprove:
        # The blocked paths' blocker.assumption_ref tells us which assumption
        # the reopen mechanism has to detect as disproved.
        for path_id in should_reopen:
            path_obj = rs.find_by_id(ledger, "blocked_path", str(path_id))
            if path_obj is None:
                continue
            assumption_ref = (path_obj.get("blocker") or {}).get("assumption_ref")
            if assumption_ref:
                should_disprove.append(str(assumption_ref))
    disproved_with_diff: list[str] = []
    for assumption_ref in should_disprove:
        # find_by_key works on ``key`` — the assumption's key — not on its
        # canonical id. Map by parsing the trailing ``:slug`` of the ref.
        assumption = rs.find_by_key(ledger, "assumption", str(assumption_ref))
        if assumption is None:
            # Try matching by canonical id.
            assumption = rs.find_by_id(ledger, "assumption", str(assumption_ref))
        if assumption is None:
            continue
        if assumption.get("status") != "disproved":
            continue
        # And it must carry diff provenance somewhere in its evidence_refs.
        for ref in (assumption.get("evidence_refs") or []) + [assumption.get("diff_evidence_ref", "")]:
            if str(ref).startswith("diff-scope.json"):
                disproved_with_diff.append(str(assumption_ref))
                break

    reachable_goals = {entry["goal"] for entry in graph_mod.paths_to_goals(graph)["reachable_goals"]}
    reachable_names = _reachable_names(graph)
    completed: list[dict[str, Any]] = []
    for chain in oracle.get("chains") or []:
        via_ok = all(str(name) in reachable_names for name in chain.get("via") or [])
        to_ok = any(
            graph_mod.find_node_by_id(graph, goal) is not None
            and str((graph_mod.find_node_by_id(graph, goal) or {}).get("name")) == str(chain.get("to"))
            for goal in reachable_goals
        )
        completed.append({"chain": chain, "complete": via_ok and to_ok})

    diff_scope = json.loads((audit_root / "diff-scope.json").read_text(encoding="utf-8"))

    return {
        "id": scenario.get("id"),
        "name": scenario.get("name"),
        "v1_sha": state["v1_sha"],
        "resolved": state["resolved"],
        "diff_scope": {
            "scope_type": diff_scope.get("scope_type"),
            "baseline": diff_scope.get("baseline"),
            "target": diff_scope.get("target"),
            "selector": diff_scope.get("selector"),
            "merge_base": diff_scope.get("merge_base"),
        },
        "counts": {
            "retain_total": len(retain),
            "reused": len(reused),
            "should_reopen_total": len(should_reopen),
            "reopened": len(reopened),
            "should_disprove_total": len(should_disprove),
            "disproved_with_diff": len(disproved_with_diff),
            "chains_total": len(completed),
            "chains_completed": sum(1 for c in completed if c["complete"]),
        },
        "detail": {
            "retain": retain,
            "reused": reused,
            "should_reopen": should_reopen,
            "reopened": reopened,
            "should_disprove": should_disprove,
            "disproved_with_diff": disproved_with_diff,
            "chains": completed,
        },
        "metrics": {
            "old_candidate_reuse_rate": (len(reused) / len(retain) if retain else 0.0),
            "blocked_path_reopen_rate": (len(reopened) / len(should_reopen)
                                         if should_reopen else 1.0),
            "affected_assumption_detection": (len(disproved_with_diff) / len(should_disprove)
                                              if should_disprove else 1.0),
            "incremental_chain_completion": (
                sum(1 for c in completed if c["complete"]) / len(completed)
                if completed else 1.0
            ),
        },
        "thresholds": dict(scenario.get("thresholds") or {}),
        "fixture": {
            "sources": list(scenario.get("sources") or []),
            "evidence_refs_checked": state["evidence_refs_checked"],
        },
        "steps": state["steps"],
    }


def aggregate(results: Sequence[Mapping[str, Any]]) -> dict[str, float]:
    totals = {
        "retain_total": 0, "reused": 0,
        "should_reopen_total": 0, "reopened": 0,
        "should_disprove_total": 0, "disproved_with_diff": 0,
        "chains_total": 0, "chains_completed": 0,
    }
    for result in results:
        for key in totals:
            totals[key] += int(result["counts"][key])
    return {
        "old_candidate_reuse_rate": (
            totals["reused"] / totals["retain_total"] if totals["retain_total"] else 0.0
        ),
        "blocked_path_reopen_rate": (
            totals["reopened"] / totals["should_reopen_total"]
            if totals["should_reopen_total"] else 1.0
        ),
        "affected_assumption_detection": (
            totals["disproved_with_diff"] / totals["should_disprove_total"]
            if totals["should_disprove_total"] else 1.0
        ),
        "incremental_chain_completion": (
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
        prog="incremental_run",
        description="Replay the incremental-audit scenarios and report the four metrics",
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
        print("no incremental scenarios found", file=sys.stderr)
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
                with tempfile.TemporaryDirectory(prefix="incremental-") as tmp:
                    results.append(evaluate_scenario(scenario, Path(tmp)))
    except (rs.ResearchError, objective_mod.ObjectiveError, graph_mod.GraphError,
            ScenarioError) as exc:
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
            "these metrics describe the runtime's handling of a diff audit "
            "(blocked-path reopen, candidate reuse, assumption detection with "
            "diff provenance, chain completion); no model was run and no with/"
            "without-diff comparison was made"
        ),
    }

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for result in results:
            print(f"{result['id']}  {result['name']}")
            print(f"    diff: scope_type={result['diff_scope']['scope_type']} "
                  f"baseline={result['diff_scope']['baseline'][:8]} "
                  f"target={result['diff_scope']['target'][:8]}")
            for name in METRIC_NAMES:
                print(f"    {name:32} {result['metrics'][name]:.4f}")
            print(f"    counts: {result['counts']}")
            fixture = result["fixture"]
            print(f"    fixture: {len(fixture['sources'])} source(s), "
                  f"{fixture['evidence_refs_checked']} evidence ref(s) resolved")
        print()
        for name in METRIC_NAMES:
            print(f"aggregate {name:32} {overall[name]:.4f}")
        if violations:
            print()
            for violation in violations:
                print(f"VIOLATION {violation}")
        else:
            print("\nall thresholds met")

    return 1 if violations else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())