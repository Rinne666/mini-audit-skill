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
    DiffRange,
    DiffRangeError,
    analyze_path_history,
    analyze_test_gaps,
    build_adversarial_plan,
    build_diff_scope,
    resolve_diff_range,
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
from . import attack_graph as graph_mod
from . import objective as objective_mod
from . import research_state as research_mod
from . import search_saturation as saturation_mod
from .attack_graph import GraphError
from .objective import ObjectiveError
from .research_state import ResearchError
from .search_lock import BUSY_EXIT_CODE, SearchLockBusy, search_governance_lock
from .sarif import normalize_sarif, normalize_sarif_file
from .sandbox import (
    EXECUTION_KINDS,
    KIND_POC,
    check_sandbox,
    evaluate_probe,
    probe_document,
    probe_file,
    run_probe_script,
    run_sandboxed,
    write_probe,
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

    ctx: dict[str, Any] = {"current_phase": phase}
    if state is not None:
        skipped = {name for name, p in state.phases.items() if p.status == PHASE_SKIPPED}
        # `required_phases` means "phases that must already be terminal before
        # *this* phase may complete". The phase being completed is by definition
        # still `in_progress` at gate time, so including it would make any gate
        # that checks terminality fail against itself. L7 declares exactly such
        # a check (`audit_state_terminal_phases`), which made `phase complete
        # L7` impossible through the CLI: L7 could never observe itself as
        # `complete` and so could never become `complete`.
        ctx["required_phases"] = [
            name for name in state.phases
            if name not in skipped and name != phase
        ]

    runner = GateRunner(workdir=workdir)
    # Cross-artifact sources (the Search Governance bundle) are assembled by the
    # runner itself from the same workdir, so a gate definition stays
    # self-contained and calling the runner directly behaves identically.
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
        # No declared gate for this phase — the deliberately-ungated set
        # (deep P4-P7/P11, confirm V1.5/V2-V6, revisit R5-R11c, merge M1-M7,
        # reinvest I1/I3, knowledge-base KB0). See SKILL.md "Gate coverage".
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


def cmd_sandbox_probe(args: argparse.Namespace) -> int:
    """Verify isolation backends by canary and write the probe document.

    Hardening v1.1.1 §2 — this replaces a probe that only recorded what the host
    *claimed* (`sandbox_available: docker exists`). Every backend is now
    exercised with a differential canary, so the probe records demonstrated
    controls.
    """
    audit_root = _resolve_audit_root(args)
    audit_root.mkdir(parents=True, exist_ok=True)
    probe = probe_document(
        args.kind,
        repo_root=args.repo_root,
        audit_root=audit_root,
        base_env=dict(os.environ),
        timeout_seconds=args.probe_timeout,
    )
    write_probe(audit_root, probe)
    decision = evaluate_probe(probe, args.kind, audit_root=audit_root)
    payload = {
        "ok": decision.ok,
        "command": "sandbox.probe",
        "probe_path": str(probe_file(audit_root)),
        "backends": [
            {
                "backend": b.get("backend"),
                "usable": b.get("usable"),
                "demonstrated": b.get("demonstrated"),
                "detail": b.get("detail"),
            }
            for b in probe["backends"]
        ],
        "decision": decision.to_dict(),
    }
    _emit(payload, exit_code=0 if decision.ok else 1)
    return 0 if decision.ok else 1


def cmd_sandbox_check(args: argparse.Namespace) -> int:
    """Evaluate the sandbox probe for an execution kind (Hardening v1.1 §8)."""
    audit_root = _resolve_audit_root(args)
    if args.run_probe:
        decision = run_probe_script(audit_root, script=args.probe_script, strict=args.strict,
                                    kind=args.kind)
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

    repo_root = getattr(args, "repo_root", None)
    result = run_sandboxed(
        argv,
        kind=args.kind,
        audit_root=audit_root,
        repo_root=repo_root,
        cwd=Path(repo_root).resolve() if repo_root else None,
        timeout_seconds=args.timeout,
        env=dict(os.environ),
    )
    payload = {"command": "sandbox.run", **result.to_dict()}
    _emit(payload, exit_code=0 if payload["ok"] else 1)
    return 0 if payload["ok"] else 1


def _resolve_diff_request(args: argparse.Namespace) -> DiffRange:
    """D0: turn whatever selector the caller used into a ``(baseline, target)``.

    Incremental auditing is only as good as its change-set: a PR audited with
    ``base..head`` instead of ``merge-base(base, head)..head`` reports the base
    branch's own commits as if this branch had reverted them — a plausible
    looking diff over the wrong question. Resolving here means the three
    selectors share one implementation.
    """
    try:
        return resolve_diff_range(
            args.repo_root,
            commit=getattr(args, "commit", None),
            since=getattr(args, "since", None),
            base=getattr(args, "base", None),
            head=getattr(args, "head", None),
            baseline=getattr(args, "baseline", None),
            target=getattr(args, "target", None),
        )
    except DiffRangeError as exc:
        _err(str(exc), code="DIFF_RANGE")
    except Exception as exc:  # noqa: BLE001
        _err(str(exc), code="DIFF_RANGE")


def cmd_diff_scope(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    resolved = _resolve_diff_request(args)
    try:
        scope = build_diff_scope(
            args.repo_root,
            baseline=resolved.baseline,
            target=resolved.target,
            risky_symbols=args.symbol or [],
            resolved_range=resolved,
        )
    except Exception as exc:  # noqa: BLE001
        _err(str(exc))
    out = audit_root / "diff-scope.json"
    write_json_atomic(out, scope.to_dict())
    _emit({"ok": True, "command": "diff.scope",
           **resolved.to_dict(),
           "changed": len(scope.changed),
           "high_risk": [c["path"] for c in scope.risk_ranked if c["risk_score"] >= 6]})
    return 0


def cmd_diff_stage(args: argparse.Namespace) -> int:
    """Run one diff-mode stage (D3/D4/D5/D6) or all of them (D3-D6)."""
    audit_root = _resolve_audit_root(args)
    audit_root.mkdir(parents=True, exist_ok=True)
    resolved = _resolve_diff_request(args)
    try:
        scope = build_diff_scope(args.repo_root, baseline=resolved.baseline,
                                 target=resolved.target,
                                 risky_symbols=args.symbol or [],
                                 resolved_range=resolved)
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
            history = analyze_path_history(args.repo_root, baseline=resolved.baseline,
                                           target=resolved.target, paths=changed_paths)
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
           **resolved.to_dict(),
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

    Deprecated since Skill-First Refactor v2 (spec §9): agent scheduling is
    a Harness responsibility. This command is no longer registered in
    ``build_parser`` — call it directly only if a Harness stub imports it.
    The Lease / ConcurrencyLease / dispatch half of ``runtime.scheduler`` is
    frozen for the same reason; ``run_command_with_timeout`` is the only
    scheduler primitive that stays live (the sandbox depends on it).

    Real agents are dispatched by the orchestrator; this command exists so
    ad-hoc CLI invocation can exercise the same code path.
    """
    import warnings
    warnings.warn(
        "cmd_run_with_lease is deprecated; agent scheduling belongs to the "
        "Harness, not the runtime.",
        DeprecationWarning,
        stacklevel=2,
    )
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


# ---------------------------------------------------------------------------
# Search Governance (Search Governance v1, R2-3 / R2-1)
# ---------------------------------------------------------------------------


def _load_json_arg(path: str, what: str) -> Any:
    p = Path(path)
    if not p.exists():
        _err(f"{what} not found at {path}")
        raise SystemExit(2)
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _err(f"{what} at {path} is not valid JSON: {exc}")
        raise SystemExit(2)


def _objective_summary(audit_root: Path, doc: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": str(objective_mod.objective_path(audit_root)),
        "revision": doc.get("revision"),
        "principal": doc.get("principal"),
        "target_capabilities": doc.get("target_capabilities"),
        "content_hash": objective_mod.content_hash(doc),
        "supersedes_count": len(doc.get("supersedes") or []),
    }


def cmd_objective_init(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    proposal = _load_json_arg(args.from_proposal, "objective proposal")
    if not isinstance(proposal, dict):
        _err("an objective proposal must be a JSON object")
    doc = objective_mod.init_and_bootstrap(
        audit_root, proposal, audit_id=getattr(args, "audit_id", None), agent=args.agent,
    )
    _emit({
        "ok": True,
        "command": "objective.init",
        "objective": _objective_summary(audit_root, doc),
        "ledger": str(research_mod.ledger_path(audit_root)),
        "graph": str(graph_mod.graph_path(audit_root)),
    })
    return 0


def cmd_objective_replace(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    if not args.force:
        _err("replacing the audit objective requires --force")
    replacement = _load_json_arg(args.from_file, "objective replacement")
    if not isinstance(replacement, dict):
        _err("an objective replacement must be a JSON object")
    doc = objective_mod.replace_and_record(
        audit_root, replacement, force=True, reason=args.reason, agent=args.agent,
    )
    _emit({
        "ok": True,
        "command": "objective.replace",
        "objective": _objective_summary(audit_root, doc),
        "superseded": (doc.get("supersedes") or [])[-1],
    })
    return 0


def cmd_objective_show(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    with search_governance_lock(audit_root, exclusive=False, operation="objective show"):
        doc = objective_mod.require_objective(audit_root)
    _emit({"ok": True, "command": "objective.show", "objective": doc,
           "content_hash": objective_mod.content_hash(doc)})
    return 0


def cmd_research_apply(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    delta = _load_json_arg(args.delta, "research delta")
    if not isinstance(delta, dict):
        _err("a research delta must be a JSON object")
    _emit(research_mod.apply_delta(audit_root, delta, agent=args.agent))
    return 0


def cmd_research_status(args: argparse.Namespace) -> int:
    _emit(research_mod.research_status(_resolve_audit_root(args)))
    return 0


def _load_graph_or_err(audit_root: Path, operation: str) -> dict[str, Any]:
    """Read the attack graph under a shared lock, with the generation checked.

    Going through ``load_research_state`` rather than reading the file directly
    means a graph left behind by an interrupted apply is refused here too,
    instead of being traversed as if it were coherent.
    """
    with search_governance_lock(audit_root, exclusive=False, operation=operation):
        state = research_mod.load_research_state(audit_root)
    graph = state.get("graph")
    if graph is None:
        _err(f"no attack graph at {graph_mod.graph_path(audit_root)}; "
             "declare an objective before querying the graph")
        raise SystemExit(2)
    return graph


def cmd_graph_show(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    graph = _load_graph_or_err(audit_root, "graph show")
    _emit({"ok": True, "command": "graph.show",
           "graph": str(graph_mod.graph_path(audit_root)),
           "summary": graph_mod.graph_summary(graph)})
    return 0


def cmd_graph_path(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    graph = _load_graph_or_err(audit_root, "graph path")
    path = graph_mod.verified_path(graph, args.from_ref, args.to_ref)
    _emit({"ok": True, "command": "graph.path", "graph": str(graph_mod.graph_path(audit_root)),
           **path})
    return 0


def cmd_graph_goals(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    graph = _load_graph_or_err(audit_root, "graph goals")
    _emit({"ok": True, "command": "graph.goals", **graph_mod.paths_to_goals(graph),
           "distance": graph_mod.goal_distance(graph)["hops_to_goal"]})
    return 0


def cmd_graph_frontier(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    graph = _load_graph_or_err(audit_root, "graph frontier")
    reachable = graph_mod.reachable_capabilities(graph)
    _emit({"ok": True, "command": "graph.frontier",
           "reachable": reachable["reachable"],
           "unreachable_verified_capabilities": reachable["unreachable_verified_capabilities"],
           "frontier": graph_mod.blocked_frontier(graph)})
    return 0


def cmd_search_saturation(args: argparse.Namespace) -> int:
    """Evaluate the completion gate and write the debt report.

    The report is derived, not research state: reading is done under the shared
    lock so the ledger and graph are one snapshot, and the write needs none.
    """
    audit_root = _resolve_audit_root(args)
    workdir = Path(getattr(args, "workdir", None) or ".").resolve()
    _emit(saturation_mod.report(audit_root, workdir=workdir))
    return 0


def cmd_snapshot(args: argparse.Namespace) -> int:
    """Build a derived one-stop view of the audit (spec §7).

    The snapshot only SELECTs / JOINs / DERIVEs / SUMMARIZEs — it does not
    rank, plan, choose, or recommend. The model reads it and decides.
    """
    from . import snapshot as snapshot_mod
    audit_root = _resolve_audit_root(args)
    out = getattr(args, "out", None)
    payload = snapshot_mod.write_snapshot(audit_root, out=out)
    _emit({"ok": True, "command": "snapshot",
           "snapshot": str(Path(out) if out else audit_root / "snapshot.json"),
           **payload})
    return 0


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

    def add_diff_selector_args(parser: argparse.ArgumentParser) -> None:
        """D0 inputs, shared by `diff scope` and `diff stage`.

        Exactly one of the four forms is accepted; `resolve_diff_range` enforces
        it rather than argparse, because the error message matters more than the
        exit path and the rule ("one selector, not two") is worth stating once.
        """
        parser.add_argument("--commit", default=None,
                            help="audit the change this one commit introduced (sha^ .. sha)")
        parser.add_argument("--since", default=None,
                            help="audit everything since a baseline sha/tag (ref .. HEAD)")
        parser.add_argument("--base", default=None,
                            help="PR base: diffed from merge-base(base, head), not from base")
        parser.add_argument("--head", default=None,
                            help="PR head (required with --base)")
        parser.add_argument("--baseline", default=None,
                            help="explicit baseline revision (escape hatch; pair with --target)")
        parser.add_argument("--target", default=None,
                            help="explicit target revision (escape hatch; pair with --baseline)")

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
                                           help="resolve the change-set and build diff scope (D0-D2)")
    s_diff_scope.add_argument("--repo-root", required=True)
    add_diff_selector_args(s_diff_scope)
    s_diff_scope.add_argument("--symbol", action="append", default=[],
                              help="risky symbol to trace (may repeat)")
    s_diff_scope.set_defaults(func=cmd_diff_scope)
    s_diff_stage = s_diff_sub.add_parser("stage", parents=[audit_root_parent],
                                         help="run diff-mode stages D3/D4/D5/D6")
    s_diff_stage.add_argument("--repo-root", required=True)
    add_diff_selector_args(s_diff_stage)
    s_diff_stage.add_argument("--stage", action="append", default=[],
                              choices=["D3", "D4", "D5", "D6", "all"],
                              help="stage to run (repeatable; default all of D3-D6)")
    s_diff_stage.add_argument("--symbol", action="append", default=[],
                              help="risky symbol for D4 blast radius (may repeat)")
    s_diff_stage.add_argument("--min-risk", type=int, default=6,
                              help="minimum risk score for D6 adversarial tasks")
    s_diff_stage.set_defaults(func=cmd_diff_stage)

    # sandbox (Hardening v1.1 §8, v1.1.1 §2)
    s_sandbox = add_sub("sandbox", help="sandbox policy operations")
    s_sandbox_sub = s_sandbox.add_subparsers(dest="subcommand", required=True)
    s_sb_probe = s_sandbox_sub.add_parser(
        "probe", parents=[audit_root_parent],
        help="verify isolation backends by canary and write the probe document",
    )
    s_sb_probe.add_argument("--kind", choices=list(EXECUTION_KINDS), default=KIND_POC)
    s_sb_probe.add_argument("--repo-root", default=".",
                            help="source tree that the sandbox must expose read-only")
    s_sb_probe.add_argument("--probe-timeout", type=float, default=45.0,
                            help="per-canary timeout in seconds")
    s_sb_probe.set_defaults(func=cmd_sandbox_probe)
    s_sb_check = s_sandbox_sub.add_parser("check", parents=[audit_root_parent],
                                          help="evaluate the sandbox probe for an execution kind")
    s_sb_check.add_argument("--kind", choices=list(EXECUTION_KINDS), default=KIND_POC)
    s_sb_check.add_argument("--run-probe", action="store_true",
                            help="run scripts/sandbox-check.sh first, then evaluate")
    s_sb_check.add_argument("--probe-script", default=None, help="override sandbox-check.sh path")
    s_sb_check.add_argument("--strict", action="store_true", help="fail on warnings when running the probe")
    s_sb_check.set_defaults(func=cmd_sandbox_check)
    s_sb_run = s_sandbox_sub.add_parser("run", parents=[audit_root_parent],
                                        help="run a command only if the sandbox policy allows it")
    s_sb_run.add_argument("--kind", choices=list(EXECUTION_KINDS), default=KIND_POC)
    s_sb_run.add_argument("--repo-root", default=None,
                          help="source tree exposed read-only inside the sandbox")
    s_sb_run.add_argument("--timeout", type=float, default=300.0)
    s_sb_run.add_argument("cmd", nargs=argparse.REMAINDER,
                          help="command to run (prefix with --)")
    s_sb_run.set_defaults(func=cmd_sandbox_run)

    # lease
    # The ``lease`` subcommand was removed in Skill-First Refactor v2 (spec §9):
    # agent scheduling belongs to the Harness, not the runtime. The function
    # ``cmd_run_with_lease`` is still importable for Harness stubs and emits a
    # DeprecationWarning, but it is no longer advertised in the CLI. The
    # ``runtime.scheduler`` module itself stays — ``run_command_with_timeout``
    # is load-bearing for the sandbox policy and ``run_command_with_timeout``
    # / ``compute_backoff`` are still unit-tested. The Lease / ConcurrencyLease
    # / dispatch half is frozen.
    # See tests/unit/test_cli.py::test_build_parser_no_longer_exposes_lease_command.

    # objective (Search Governance control plane, R2-3)
    s_objective = add_sub("objective", help="audit objective operations")
    s_objective_sub = s_objective.add_subparsers(dest="subcommand", required=True)

    s_obj_init = s_objective_sub.add_parser("init", parents=[audit_root_parent],
                                            help="promote an L1 objective proposal")
    s_obj_init.add_argument("--from-proposal", required=True,
                            help="path to agents/<id>/scratch/objective-proposal.json")
    s_obj_init.add_argument("--audit-id", default=None)
    s_obj_init.add_argument("--agent", default=None, help="recorded in the lock file")
    s_obj_init.set_defaults(func=cmd_objective_init)

    s_obj_replace = s_objective_sub.add_parser(
        "replace", parents=[audit_root_parent],
        help="revise the objective (both --force and --reason are required)")
    s_obj_replace.add_argument("--from", dest="from_file", required=True,
                               help="path to the replacement objective JSON")
    s_obj_replace.add_argument("--force", action="store_true", required=True,
                               help="required: replacing an objective is never implicit")
    s_obj_replace.add_argument("--reason", required=True,
                               help="required: a replaced objective must record why")
    s_obj_replace.add_argument("--agent", default=None, help="recorded in the lock file")
    s_obj_replace.set_defaults(func=cmd_objective_replace)

    s_obj_show = s_objective_sub.add_parser("show", parents=[audit_root_parent],
                                            help="show the canonical objective")
    s_obj_show.set_defaults(func=cmd_objective_show)

    # research (Search Governance research plane, R2-1)
    s_research = add_sub("research", help="research state operations")
    s_research_sub = s_research.add_subparsers(dest="subcommand", required=True)

    s_res_apply = s_research_sub.add_parser(
        "apply", parents=[audit_root_parent],
        help="apply a research delta; succeeds whole or changes nothing")
    s_res_apply.add_argument("delta", help="path to research-delta.json")
    s_res_apply.add_argument("--agent", default=None, help="recorded in the lock file")
    s_res_apply.set_defaults(func=cmd_research_apply)

    s_res_status = s_research_sub.add_parser("status", parents=[audit_root_parent],
                                             help="summarise the research state")
    s_res_status.set_defaults(func=cmd_research_status)

    # graph (Search Governance attack graph queries, R2-6 / Phase B)
    s_graph = add_sub("graph", help="attack graph queries")
    s_graph_sub = s_graph.add_subparsers(dest="subcommand", required=True)

    s_gr_show = s_graph_sub.add_parser("show", parents=[audit_root_parent],
                                       help="summarise the attack graph")
    s_gr_show.set_defaults(func=cmd_graph_show)

    s_gr_path = s_graph_sub.add_parser("path", parents=[audit_root_parent],
                                       help="shortest verified-edge path between two nodes")
    s_gr_path.add_argument("--from", dest="from_ref", required=True,
                           help="canonical node id (CAP-002) or semantic key")
    s_gr_path.add_argument("--to", dest="to_ref", required=True,
                           help="canonical node id (GOAL-001) or semantic key")
    s_gr_path.set_defaults(func=cmd_graph_path)

    s_gr_goals = s_graph_sub.add_parser("goals", parents=[audit_root_parent],
                                        help="which declared goals are verified reachable")
    s_gr_goals.set_defaults(func=cmd_graph_goals)

    s_gr_frontier = s_graph_sub.add_parser("frontier", parents=[audit_root_parent],
                                           help="next unverified edges at the reachable boundary")
    s_gr_frontier.set_defaults(func=cmd_graph_frontier)

    # search (Search Governance — verification only; planning is a Skill policy)
    s_search = add_sub("search", help="search governance verification")
    s_search_sub = s_search.add_subparsers(dest="subcommand", required=True)

    s_search_sat = s_search_sub.add_parser(
        "saturation", parents=[audit_root_parent],
        help="evaluate the completion gate and write mini-audit/search-saturation.json")
    s_search_sat.add_argument("--workdir", default=".",
                              help="directory evidence references resolve against (default: cwd)")
    s_search_sat.set_defaults(func=cmd_search_saturation)

    # snapshot — spec §7 read-only derived view
    s_snapshot = add_sub("snapshot", help="build a one-stop read-only view of audit state")
    s_snapshot.add_argument("--out", default=None,
                            help="write the snapshot to PATH (default: <audit-root>/snapshot.json)")
    s_snapshot.set_defaults(func=cmd_snapshot)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except SearchLockBusy as exc:
        # A busy Search Governance lock is a retryable condition, not a bad
        # request, so it gets its own exit code (3) and a machine-readable
        # holder, rather than being folded into the generic failure path.
        _emit(exc.to_dict(), exit_code=BUSY_EXIT_CODE)
        return BUSY_EXIT_CODE
    except (StateTransitionError, AtomicIOError, FindingValidationError,
            CoverageLedgerError, GateError, SourceIdentityError,
            ObjectiveError, ResearchError, GraphError, ValueError) as exc:
        code = getattr(exc, "code", None)
        if code:
            _err(str(exc), code=code)
        else:
            _err(str(exc))
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())