"""Runtime CLI dispatcher (Spec §7).

Spec §7 contract:

    mini-audit-runtime state init
    mini-audit-runtime state show
    mini-audit-runtime phase start L5
    mini-audit-runtime phase complete L5
    mini-audit-runtime phase fail L5 --error "..."
    mini-audit-runtime gate L5
    mini-audit-runtime finding validate <file>
    mini-audit-runtime coverage validate
    mini-audit-runtime export --format json

The CLI is intentionally thin — every command delegates to a module in
:mod:`runtime`. The CLI's job is argument parsing, exit codes, and
machine-readable output.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from . import __version__
from .atomic_io import (
    AtomicIOError,
    sha256_file,
    write_json_atomic,
)
from .coverage import (
    PLANNING_COMPLETE as COVERAGE_PLANNING_COMPLETE,
    CoverageLedger,
    CoverageLedgerError,
    CoverageUnit,
    make_unit_id,
)
from .diff_scope import (
    analyze_path_history,
    analyze_test_gaps,
    build_adversarial_plan,
    build_diff_scope,
    structured_blast_radius,
)
from .export import Exporter
from .findings import (
    FindingStore,
    FindingValidationError,
    compute_fingerprint,
    validate_finding,
)
from .gates import GateError, GateResult, GateRunner, gate_for, has_gate
from .sarif import normalize_sarif, normalize_sarif_file
from .sandbox import (
    EXECUTION_KINDS,
    KIND_POC,
    check_sandbox,
    run_probe_script,
    run_sandboxed,
)
from .scheduler import DEFAULT_CONFIG, dispatch
from .source_identity import SourceIdentity, SourceIdentityError
from .state import (
    PHASE_COMPLETE,
    PHASE_FAILED,
    PHASE_IN_PROGRESS,
    PHASE_PENDING,
    PHASE_SKIPPED,
    AuditState,
    StateTransitionError,
)

DEFAULT_AUDIT_ROOT = "mini-audit"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _emit(payload: Any, *, exit_code: int = 0, as_json: bool = True) -> None:
    if as_json:
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    else:
        if isinstance(payload, (dict, list)):
            sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        else:
            sys.stdout.write(str(payload) + "\n")
    sys.stdout.flush()
    if exit_code:
        sys.exit(exit_code)


def _err(message: str, **extra: Any) -> None:
    payload = {"ok": False, "error": message, **extra}
    sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    sys.stdout.flush()
    sys.exit(2)


def _resolve_audit_root(args: argparse.Namespace) -> Path:
    root = getattr(args, "audit_root", None) or DEFAULT_AUDIT_ROOT
    return Path(root)


def _load_state(audit_root: Path) -> AuditState:
    state_path = audit_root / "audit-state.json"
    if not state_path.exists():
        raise StateTransitionError(f"audit-state.json not found at {state_path}")
    return AuditState.load(state_path)


def _save_state(state: AuditState, audit_root: Path) -> None:
    state.save(audit_root / "audit-state.json")


def _runtime_info() -> dict[str, Any]:
    return {
        "version": __version__,
        "agent_sdk": os.environ.get("MAVIS_AGENT_SDK", "mavis"),
        "model": os.environ.get("MAVIS_MODEL", "unknown"),
    }


def _run_phase_gate(audit_root: Path, phase: str, workdir: Path,
                    state: Optional[AuditState] = None) -> GateResult:
    """Run the declared gate for *phase* (Hardening v1.1 §2/§3/§4/§5).

    Returns the raw :class:`GateResult`. The caller decides whether a failure
    is fatal. Raises :class:`GateError` when the phase has no gate at all, so
    callers can distinguish "no gate declared" from "gate failed".
    """
    gate_def = gate_for(phase)

    ctx: dict[str, Any] = {}
    if state is not None:
        skipped = {name for name, p in state.phases.items() if p.status == PHASE_SKIPPED}
        ctx["required_phases"] = [
            name for name in state.phases if name not in skipped
        ]

    runner = GateRunner(workdir=workdir)
    # No pre-seeded semantic data: every semantic check declares its own
    # artifact and the runner loads it from disk (v1.1 §3).
    return runner.run(gate_def, semantic_data={}, ctx=ctx)


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_state_init(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    audit_root.mkdir(parents=True, exist_ok=True)
    state_path = audit_root / "audit-state.json"
    source_identity = SourceIdentity.capture(args.repo_root)
    audit_id = args.audit_id or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    state = AuditState.new(
        audit_id=audit_id,
        mode=args.mode,
        source=source_identity.to_dict(),
        runtime=_runtime_info(),
    )
    state.save(state_path)
    _emit({"ok": True, "command": "state.init", "audit_id": audit_id, "audit_root": str(audit_root)})
    return 0


def cmd_state_show(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        state = _load_state(audit_root)
    except StateTransitionError as exc:
        _err(str(exc))
    _emit({"ok": True, "state": state.to_dict()})
    return 0


def cmd_phase_start(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        state = _load_state(audit_root)
        state.transition(args.phase, to=PHASE_IN_PROGRESS, reset=bool(getattr(args, "reset", False)))
        state.heartbeat(args.phase)
        _save_state(state, audit_root)
    except (StateTransitionError, AtomicIOError) as exc:
        _err(str(exc))
    phase = state.phases[args.phase]
    _emit({"ok": True, "command": "phase.start", "phase": args.phase,
           "status": PHASE_IN_PROGRESS, "attempt": phase.attempt,
           "max_attempts": phase.max_attempts})
    return 0


def cmd_phase_complete(args: argparse.Namespace) -> int:
    """Complete a phase — but only if its gate passes (Hardening v1.1 §2).

    There is no bypass. ``phase complete L6`` used to advance state on the
    agent's word alone, which made every gate advisory. Now the runtime runs
    the declared gate for the phase first:

        phase complete → gate → PASS → complete
                             ↘ FAIL → failed (or stay in_progress)

    A failed gate leaves the phase non-complete and exits non-zero.
    """
    audit_root = _resolve_audit_root(args)
    workdir = Path(getattr(args, "workdir", None) or ".").resolve()
    try:
        state = _load_state(audit_root)
    except (StateTransitionError, AtomicIOError) as exc:
        _err(str(exc))

    gate_result: Optional[GateResult] = None
    if has_gate(args.phase):
        try:
            gate_result = _run_phase_gate(audit_root, args.phase, workdir, state=state)
        except GateError as exc:
            _err(f"gate error for {args.phase}: {exc}")
        if not gate_result.passed:
            summary = "; ".join(f"{f.check}:{f.message}" for f in gate_result.failures[:4])
            # Keep the phase from ever reaching `complete` on a failed gate.
            try:
                current = state.phases.get(args.phase)
                if current is not None and current.status == PHASE_IN_PROGRESS:
                    state.transition(args.phase, to=PHASE_FAILED, error=f"gate failed: {summary}")
                _save_state(state, audit_root)
            except (StateTransitionError, AtomicIOError):
                pass
            _emit(
                {
                    "ok": False,
                    "command": "phase.complete",
                    "phase": args.phase,
                    "status": (state.phases.get(args.phase).status if args.phase in state.phases else None),
                    "error": f"gate failed: {summary}",
                    "gate": gate_result.to_dict(),
                },
                exit_code=1,
            )
            return 1
    else:
        # No declared gate for this phase (e.g. lite Q-phases, V/R/M phases).
        # Record that explicitly rather than silently pretending it passed.
        gate_result = GateResult(name=args.phase, passed=True)
        gate_result.add_note(f"no default gate declared for phase {args.phase!r}; gate skipped")

    try:
        state.transition(args.phase, to=PHASE_COMPLETE)
        _save_state(state, audit_root)
    except (StateTransitionError, AtomicIOError) as exc:
        _err(str(exc))
    _emit({"ok": True, "command": "phase.complete", "phase": args.phase,
           "status": PHASE_COMPLETE, "gate": gate_result.to_dict()})
    return 0


def cmd_phase_fail(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        state = _load_state(audit_root)
        state.transition(args.phase, to=PHASE_FAILED, error=args.error)
        _save_state(state, audit_root)
    except StateTransitionError as exc:
        _err(str(exc))
    _emit({"ok": True, "command": "phase.fail", "phase": args.phase, "status": PHASE_FAILED, "error": args.error})
    return 0


def cmd_phase_skip(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        state = _load_state(audit_root)
        state.transition(args.phase, to=PHASE_SKIPPED)
        _save_state(state, audit_root)
    except StateTransitionError as exc:
        _err(str(exc))
    _emit({"ok": True, "command": "phase.skip", "phase": args.phase, "status": PHASE_SKIPPED})
    return 0


def cmd_gate(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    workdir = Path(args.workdir or ".").resolve()

    state: Optional[AuditState] = None
    try:
        state = _load_state(audit_root)
    except (StateTransitionError, AtomicIOError):
        state = None

    try:
        result = _run_phase_gate(audit_root, args.phase, workdir, state=state)
    except GateError as exc:
        _err(f"unknown gate for phase {args.phase}: {exc}")
        return 2

    payload = {"ok": result.passed, "command": "gate", "phase": args.phase, "result": result.to_dict()}
    _emit(payload, exit_code=0 if result.passed else 1)
    return 0 if result.passed else 1


def cmd_finding_validate(args: argparse.Namespace) -> int:
    try:
        data = json.loads(Path(args.finding_file).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        _err(f"cannot read {args.finding_file}: {exc}")

    if isinstance(data, dict) and "findings" in data:
        # Multiple findings (canonical store)
        try:
            store = FindingStore.from_dict(data)
        except FindingValidationError as exc:
            _emit({"ok": False, "command": "finding.validate", "errors": [str(exc)]}, exit_code=1)
            return 1
        stats = store.stats()
        _emit({"ok": True, "command": "finding.validate", "stats": stats, "count": stats["total"]})
        return 0

    try:
        validate_finding(data)
        fp = compute_fingerprint(data)
    except FindingValidationError as exc:
        _emit({"ok": False, "command": "finding.validate", "errors": [str(exc)]}, exit_code=1)
        return 1
    _emit({"ok": True, "command": "finding.validate", "fingerprint": fp, "verdict": data.get("verdict")})
    return 0


def cmd_finding_upsert(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        data = json.loads(Path(args.finding_file).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        _err(f"cannot read {args.finding_file}: {exc}")

    if isinstance(data, dict) and "findings" in data:
        findings = data.get("findings") or []
    elif isinstance(data, list):
        findings = data
    else:
        findings = [data]

    findings_path = audit_root / "findings.json"
    try:
        store = FindingStore.load(findings_path)
    except AtomicIOError as exc:
        _err(str(exc))

    added = 0
    updated = 0
    for f in findings:
        before = store.get(f.get("fingerprint") or compute_fingerprint(f)) is not None
        store.upsert(f)
        if before:
            updated += 1
        else:
            added += 1

    store.save(findings_path)
    _emit({"ok": True, "command": "finding.upsert", "added": added, "updated": updated,
           "stats": store.stats()})
    return 0


def cmd_coverage_validate(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    ledger_path = audit_root / "coverage-ledger.json"
    try:
        ledger = CoverageLedger.load(ledger_path)
    except (AtomicIOError, CoverageLedgerError) as exc:
        _err(str(exc))
    report = ledger.completeness_report()
    payload = {"ok": report["ok"], "command": "coverage.validate", **report}
    _emit(payload, exit_code=0 if report["ok"] else 1)
    return 0 if report["ok"] else 1


def cmd_coverage_init(args: argparse.Namespace) -> int:
    """Initialize a coverage-ledger.json from a YAML/JSON plan."""
    audit_root = _resolve_audit_root(args)
    try:
        plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        _err(f"cannot read coverage plan {args.plan}: {exc}")

    units = plan.get("units") or []
    planning_status = plan.get("planning_status") or COVERAGE_PLANNING_COMPLETE
    try:
        ledger = CoverageLedger(
            audit_id=plan.get("audit_id", ""),
            units=[CoverageUnit.from_dict(u) for u in units],
            planning_status=planning_status,
        )
        ledger.save(audit_root / "coverage-ledger.json")
    except (AtomicIOError, CoverageLedgerError) as exc:
        _err(str(exc))
    report = ledger.completeness_report()
    _emit({"ok": True, "command": "coverage.init", "count": ledger.unit_count(),
           "planning_status": ledger.planning_status,
           "complete_ok": report["ok"], "reasons": report["reasons"]})
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    findings_path = audit_root / "findings.json"
    try:
        store = FindingStore.load(findings_path)
    except AtomicIOError as exc:
        _err(str(exc))

    exporter = Exporter(store)
    out_path = args.output or f"{audit_root}/reports/findings.{args.format}"
    n = exporter.export(
        fmt=args.format,
        path=out_path,
        verdict=args.verdict,
        min_severity=args.min_severity,
        cls=args.cls,
        since=args.since,
    )
    _emit({"ok": True, "command": "export", "format": args.format,
           "path": str(out_path), "count": n})
    return 0


def cmd_source_capture(args: argparse.Namespace) -> int:
    try:
        identity = SourceIdentity.capture(args.repo_root)
    except SourceIdentityError as exc:
        _err(str(exc))
    _emit({"ok": True, "command": "source.capture", "identity": identity.to_dict()})
    return 0


def cmd_source_diff(args: argparse.Namespace) -> int:
    try:
        new_id = SourceIdentity.capture(args.repo_root)
    except SourceIdentityError as exc:
        _err(str(exc))

    audit_root = _resolve_audit_root(args)
    try:
        state = _load_state(audit_root)
    except StateTransitionError as exc:
        _err(str(exc))

    stored = SourceIdentity.from_dict(state.source) if state.source else None
    diff = stored.diff_summary(new_id) if stored else {"stored": None}
    matches = stored.matches(new_id) if stored else False
    payload = {
        "ok": True,
        "command": "source.diff",
        "matches": matches,
        "diff": diff,
        "stored": stored.to_dict() if stored else None,
        "current": new_id.to_dict(),
    }
    _emit(payload)
    return 0


def cmd_sarif_normalize(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        candidates = normalize_sarif_file(args.sarif, source=args.source)
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as exc:
        _err(f"cannot normalize {args.sarif}: {exc}")
    out_dir = audit_root / "candidates"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{args.source}-candidates.json"
    write_json_atomic(out_path, {
        "schema_version": 1,
        "source": args.source,
        "count": len(candidates),
        "candidates": candidates,
    })
    _emit({"ok": True, "command": "sarif.normalize", "count": len(candidates), "path": str(out_path)})
    return 0


def cmd_sandbox_check(args: argparse.Namespace) -> int:
    """Evaluate the sandbox probe for an execution kind (Hardening v1.1 §8)."""
    audit_root = _resolve_audit_root(args)
    if args.run_probe:
        decision = run_probe_script(audit_root, script=args.probe_script, strict=args.strict)
    else:
        decision = check_sandbox(args.kind, audit_root)
    payload = {"ok": decision.ok, "command": "sandbox.check", **decision.to_dict()}
    _emit(payload, exit_code=0 if decision.ok else 1)
    return 0 if decision.ok else 1


def cmd_sandbox_run(args: argparse.Namespace) -> int:
    """Run a command only if the sandbox policy allows it. No host fallback."""
    audit_root = _resolve_audit_root(args)
    argv = list(args.cmd or [])
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        _err("sandbox run requires a command after --")

    result = run_sandboxed(
        argv,
        kind=args.kind,
        audit_root=audit_root,
        timeout_seconds=args.timeout,
        env=dict(os.environ),
    )
    payload = {"command": "sandbox.run", **result.to_dict()}
    _emit(payload, exit_code=0 if payload["ok"] else 1)
    return 0 if payload["ok"] else 1


def cmd_diff_scope(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        scope = build_diff_scope(
            args.repo_root,
            baseline=args.baseline,
            target=args.target,
            risky_symbols=args.symbol or [],
        )
    except Exception as exc:  # noqa: BLE001
        _err(str(exc))
    out = audit_root / "diff-scope.json"
    write_json_atomic(out, scope.to_dict())
    _emit({"ok": True, "command": "diff.scope",
           "changed": len(scope.changed), "high_risk": [c["path"] for c in scope.risk_ranked if c["risk_score"] >= 6]})
    return 0


def cmd_diff_stage(args: argparse.Namespace) -> int:
    """Run one diff-mode stage (D3/D4/D5/D6) or all of them (D3-D6)."""
    audit_root = _resolve_audit_root(args)
    audit_root.mkdir(parents=True, exist_ok=True)
    try:
        scope = build_diff_scope(args.repo_root, baseline=args.baseline, target=args.target,
                                 risky_symbols=args.symbol or [])
    except Exception as exc:  # noqa: BLE001
        _err(str(exc))

    changed_paths = [c["path"] for c in scope.changed]
    stages = args.stage or ["D3", "D4", "D5", "D6"]
    if "all" in stages:
        stages = ["D3", "D4", "D5", "D6"]

    written: list[str] = []
    payloads: dict[str, Any] = {}
    for stage in stages:
        if stage == "D3":
            history = analyze_path_history(args.repo_root, baseline=args.baseline,
                                           target=args.target, paths=changed_paths)
            payload = {k: v.to_dict() for k, v in history.items()}
        elif stage == "D4":
            payload = structured_blast_radius(args.repo_root, changed_paths=changed_paths,
                                             symbols=args.symbol or [])
        elif stage == "D5":
            payload = analyze_test_gaps(args.repo_root, changed_paths=changed_paths,
                                        changed_line_ranges=scope.line_ranges)
        elif stage == "D6":
            payload = build_adversarial_plan(args.repo_root, risk_ranked=scope.risk_ranked,
                                             line_ranges=scope.line_ranges,
                                             min_risk=args.min_risk)
        else:
            _err(f"unknown diff stage {stage!r}; expected D3, D4, D5, D6 or all")

        out = audit_root / f"diff-{stage.lower()}.json"
        write_json_atomic(out, payload)
        written.append(str(out))
        payloads[stage] = payload

    _emit({"ok": True, "command": "diff.stage", "stages": stages,
           "changed": len(scope.changed), "artifacts": written,
           "summary": {
               "D3_paths_with_history": len(payloads.get("D3", {})),
               "D4_symbols": len(payloads.get("D4", {}).get("symbols", [])),
               "D5_gap_risk": payloads.get("D5", {}).get("gap_risk"),
               "D5_untested": len(payloads.get("D5", {}).get("untested_paths", [])),
               "D6_tasks": payloads.get("D6", {}).get("task_count"),
           }})
    return 0



def cmd_run_with_lease(args: argparse.Namespace) -> int:
    """Run a registered agent function under the scheduler.

    The runtime hosts a small registry of common tasks (validate-finding,
    fingerprint, etc.) that can be invoked with deterministic retry/timeout.
    Real agents are dispatched by the orchestrator; this command exists so
    ad-hoc CLI invocation can exercise the same code path.
    """
    cfg = dict(DEFAULT_CONFIG)
    if args.config:
        cfg.update(json.loads(Path(args.config).read_text(encoding="utf-8")))

    registry: dict[str, Any] = {
        "validate-finding": _task_validate_finding,
        "fingerprint": _task_fingerprint,
    }
    fn = registry.get(args.task)
    if fn is None:
        _err(f"unknown task {args.task!r}; registered: {sorted(registry)}")

    outcome = dispatch(
        workdir=Path(args.workdir or "."),
        role=args.task,
        phase=args.phase or "adhoc",
        fn=fn,
        config=cfg,
        timeout_seconds=args.timeout,
        max_attempts=args.max_attempts,
        agent_id=args.agent_id,
    )
    payload = {
        "ok": outcome.success,
        "command": "lease.run",
        "task": args.task,
        "agent_id": outcome.agent_id,
        "attempts": outcome.attempts,
        "elapsed_seconds": round(outcome.elapsed_seconds, 3),
        "timed_out": outcome.timed_out,
        "result": outcome.result,
        "error": outcome.error,
    }
    _emit(payload, exit_code=0 if outcome.success else 1)
    return 0 if outcome.success else 1


def _task_validate_finding(lease: Any) -> dict[str, Any]:
    """Example task: validate the first finding in findings.json."""
    from .findings import FindingStore

    findings_path = lease.workdir / "findings.json"
    if not findings_path.exists():
        return {"success": False, "error": "findings.json missing"}
    store = FindingStore.load(findings_path)
    if not store.findings:
        return {"success": True, "validated": 0}
    for f in store.findings:
        validate_finding(f)
    return {"success": True, "validated": len(store.findings)}


def _task_fingerprint(lease: Any) -> dict[str, Any]:
    """Example task: recompute fingerprints for all findings."""
    from .findings import FindingStore

    findings_path = lease.workdir / "findings.json"
    if not findings_path.exists():
        return {"success": False, "error": "findings.json missing"}
    store = FindingStore.load(findings_path)
    for f in store.findings:
        f["fingerprint"] = compute_fingerprint(f)
    store.save(findings_path)
    return {"success": True, "count": len(store.findings)}


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mini-audit-runtime",
        description="mini-audit-skill deterministic runtime",
    )
    p.add_argument("--version", action="version", version=f"mini-audit-runtime {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    # Parent parser that supplies --audit-root to every subcommand.
    audit_root_parent = argparse.ArgumentParser(add_help=False)
    audit_root_parent.add_argument(
        "--audit-root", default=DEFAULT_AUDIT_ROOT,
        help="path to mini-audit/ audit directory (default: %(default)s)",
    )

    def add_sub(name: str, **kwargs) -> argparse.ArgumentParser:
        kwargs.setdefault("parents", [audit_root_parent])
        return sub.add_parser(name, **kwargs)

    # state
    s_state = add_sub("state", help="audit-state operations")
    s_state_sub = s_state.add_subparsers(dest="subcommand", required=True)
    s_init = s_state_sub.add_parser("init", parents=[audit_root_parent], help="initialize audit state")
    s_init.add_argument("--repo-root", required=True, help="repository to audit")
    s_init.add_argument("--mode", default="balanced", help="audit mode (lite/balanced/deep)")
    s_init.add_argument("--audit-id", default=None, help="explicit audit id")
    s_init.set_defaults(func=cmd_state_init)
    s_show = s_state_sub.add_parser("show", parents=[audit_root_parent], help="show audit state")
    s_show.set_defaults(func=cmd_state_show)

    # phase
    s_phase = add_sub("phase", help="phase transitions")
    s_phase_sub = s_phase.add_subparsers(dest="subcommand", required=True)
    for action, target in [("start", PHASE_IN_PROGRESS),
                            ("complete", PHASE_COMPLETE),
                            ("fail", PHASE_FAILED),
                            ("skip", PHASE_SKIPPED)]:
        sp = s_phase_sub.add_parser(action, parents=[audit_root_parent],
                                    help=f"transition phase to {target}")
        sp.add_argument("phase", help="phase name (e.g. L5)")
        if action == "fail":
            sp.add_argument("--error", required=True, help="error description")
        if action == "start":
            sp.add_argument("--reset", action="store_true",
                            help="reset the attempt budget (required once max_attempts is exhausted)")
        if action == "complete":
            sp.add_argument("--workdir", default=".",
                            help="directory the phase artifacts are resolved against (default: cwd)")
        sp.set_defaults(func=getattr(sys.modules[__name__], f"cmd_phase_{action}"))

    # gate
    s_gate = add_sub("gate", help="run phase gate")
    s_gate.add_argument("phase", help="phase name")
    s_gate.add_argument("--workdir", default=".", help="working directory (default: cwd)")
    s_gate.set_defaults(func=cmd_gate)

    # finding
    s_finding = add_sub("finding", help="finding operations")
    s_finding_sub = s_finding.add_subparsers(dest="subcommand", required=True)
    s_validate = s_finding_sub.add_parser("validate", parents=[audit_root_parent],
                                           help="validate a finding file")
    s_validate.add_argument("finding_file", help="path to finding JSON")
    s_validate.set_defaults(func=cmd_finding_validate)
    s_upsert = s_finding_sub.add_parser("upsert", parents=[audit_root_parent],
                                          help="upsert findings into canonical store")
    s_upsert.add_argument("finding_file", help="path to finding JSON or canonical store")
    s_upsert.set_defaults(func=cmd_finding_upsert)

    # coverage
    s_coverage = add_sub("coverage", help="coverage ledger operations")
    s_coverage_sub = s_coverage.add_subparsers(dest="subcommand", required=True)
    s_cov_val = s_coverage_sub.add_parser("validate", parents=[audit_root_parent],
                                            help="validate coverage ledger")
    s_cov_val.set_defaults(func=cmd_coverage_validate)
    s_cov_init = s_coverage_sub.add_parser("init", parents=[audit_root_parent],
                                            help="initialize from plan")
    s_cov_init.add_argument("plan", help="plan JSON path")
    s_cov_init.set_defaults(func=cmd_coverage_init)

    # export
    s_export = add_sub("export", help="export findings")
    s_export.add_argument("--format", choices=["json", "md", "markdown", "sarif"], required=True)
    s_export.add_argument("--output", default=None, help="output path")
    s_export.add_argument("--verdict", default=None, help="filter by verdict")
    s_export.add_argument("--min-severity", default=None, help="minimum severity")
    s_export.add_argument("--class", dest="cls", default=None, help="filter by class")
    s_export.add_argument("--since", default=None, help="ISO timestamp filter")
    s_export.set_defaults(func=cmd_export)

    # source
    s_source = add_sub("source", help="source identity operations")
    s_source_sub = s_source.add_subparsers(dest="subcommand", required=True)
    s_src_cap = s_source_sub.add_parser("capture", parents=[audit_root_parent],
                                         help="capture current source identity")
    s_src_cap.add_argument("--repo-root", required=True)
    s_src_cap.set_defaults(func=cmd_source_capture)
    s_src_diff = s_source_sub.add_parser("diff", parents=[audit_root_parent],
                                          help="diff against stored identity")
    s_src_diff.add_argument("--repo-root", required=True)
    s_src_diff.set_defaults(func=cmd_source_diff)

    # sarif
    s_sarif = add_sub("sarif", help="SARIF operations")
    s_sarif_sub = s_sarif.add_subparsers(dest="subcommand", required=True)
    s_sarif_norm = s_sarif_sub.add_parser("normalize", parents=[audit_root_parent],
                                            help="normalize SARIF → candidates")
    s_sarif_norm.add_argument("sarif", help="SARIF file path")
    s_sarif_norm.add_argument("--source", default="scanner", help="scanner source name")
    s_sarif_norm.set_defaults(func=cmd_sarif_normalize)

    # diff
    s_diff = add_sub("diff", help="diff mode operations")
    s_diff_sub = s_diff.add_subparsers(dest="subcommand", required=True)
    s_diff_scope = s_diff_sub.add_parser("scope", parents=[audit_root_parent],
                                           help="build diff scope")
    s_diff_scope.add_argument("--repo-root", required=True)
    s_diff_scope.add_argument("--baseline", required=True)
    s_diff_scope.add_argument("--target", required=True)
    s_diff_scope.add_argument("--symbol", action="append", default=[],
                              help="risky symbol to trace (may repeat)")
    s_diff_scope.set_defaults(func=cmd_diff_scope)
    s_diff_stage = s_diff_sub.add_parser("stage", parents=[audit_root_parent],
                                         help="run diff-mode stages D3/D4/D5/D6")
    s_diff_stage.add_argument("--repo-root", required=True)
    s_diff_stage.add_argument("--baseline", required=True)
    s_diff_stage.add_argument("--target", required=True)
    s_diff_stage.add_argument("--stage", action="append", default=[],
                              choices=["D3", "D4", "D5", "D6", "all"],
                              help="stage to run (repeatable; default all of D3-D6)")
    s_diff_stage.add_argument("--symbol", action="append", default=[],
                              help="risky symbol for D4 blast radius (may repeat)")
    s_diff_stage.add_argument("--min-risk", type=int, default=6,
                              help="minimum risk score for D6 adversarial tasks")
    s_diff_stage.set_defaults(func=cmd_diff_stage)

    # sandbox (Hardening v1.1 §8)
    s_sandbox = add_sub("sandbox", help="sandbox policy operations")
    s_sandbox_sub = s_sandbox.add_subparsers(dest="subcommand", required=True)
    s_sb_check = s_sandbox_sub.add_parser("check", parents=[audit_root_parent],
                                          help="evaluate sandbox capabilities for an execution kind")
    s_sb_check.add_argument("--kind", choices=list(EXECUTION_KINDS), default=KIND_POC)
    s_sb_check.add_argument("--run-probe", action="store_true",
                            help="run scripts/sandbox-check.sh first, then evaluate")
    s_sb_check.add_argument("--probe-script", default=None, help="override sandbox-check.sh path")
    s_sb_check.add_argument("--strict", action="store_true", help="fail on warnings when running the probe")
    s_sb_check.set_defaults(func=cmd_sandbox_check)
    s_sb_run = s_sandbox_sub.add_parser("run", parents=[audit_root_parent],
                                        help="run a command only if the sandbox policy allows it")
    s_sb_run.add_argument("--kind", choices=list(EXECUTION_KINDS), default=KIND_POC)
    s_sb_run.add_argument("--timeout", type=float, default=300.0)
    s_sb_run.add_argument("cmd", nargs=argparse.REMAINDER,
                          help="command to run (prefix with --)")
    s_sb_run.set_defaults(func=cmd_sandbox_run)

    # lease
    s_lease = add_sub("lease", help="run a registered task under scheduler policy")
    s_lease_sub = s_lease.add_subparsers(dest="subcommand", required=True)
    s_lease_run = s_lease_sub.add_parser("run", help="run a task")
    s_lease_run.add_argument("task", help="task name (validate-finding, fingerprint, ...)")
    s_lease_run.add_argument("--phase", default="adhoc")
    s_lease_run.add_argument("--workdir", default=".")
    s_lease_run.add_argument("--config", default=None)
    s_lease_run.add_argument("--timeout", type=int, default=None)
    s_lease_run.add_argument("--max-attempts", type=int, default=None)
    s_lease_run.add_argument("--agent-id", default=None)
    s_lease_run.set_defaults(func=cmd_run_with_lease)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except (StateTransitionError, AtomicIOError, FindingValidationError,
            CoverageLedgerError, GateError, SourceIdentityError, ValueError) as exc:
        _err(str(exc))
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())