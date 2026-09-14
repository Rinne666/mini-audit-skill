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
from typing import Any, Sequence

from . import __version__
from .atomic_io import (
    AtomicIOError,
    sha256_file,
    write_json_atomic,
)
from .coverage import CoverageLedger, make_unit_id
from .diff_scope import build_diff_scope
from .export import Exporter
from .findings import (
    FindingStore,
    FindingValidationError,
    compute_fingerprint,
    validate_finding,
)
from .gates import GateResult, GateRunner, gate_for
from .sarif import normalize_sarif, normalize_sarif_file
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
        state.transition(args.phase, to=PHASE_IN_PROGRESS)
        state.heartbeat(args.phase)
        _save_state(state, audit_root)
    except (StateTransitionError, AtomicIOError) as exc:
        _err(str(exc))
    _emit({"ok": True, "command": "phase.start", "phase": args.phase, "status": PHASE_IN_PROGRESS})
    return 0


def cmd_phase_complete(args: argparse.Namespace) -> int:
    audit_root = _resolve_audit_root(args)
    try:
        state = _load_state(audit_root)
        state.transition(args.phase, to=PHASE_COMPLETE)
        _save_state(state, audit_root)
    except StateTransitionError as exc:
        _err(str(exc))
    _emit({"ok": True, "command": "phase.complete", "phase": args.phase, "status": PHASE_COMPLETE})
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
    try:
        gate_def = gate_for(args.phase)
    except Exception as exc:  # noqa: BLE001
        _err(f"unknown gate for phase {args.phase}: {exc}")

    runner = GateRunner(workdir=Path(args.workdir or ".").resolve())
    semantic_data: dict[str, Any] = {}

    ctx: dict[str, Any] = {}
    # The L7 audit_state_terminal_phases semantic needs all phases known to
    # audit-state.json. Look them up from state.
    try:
        state = _load_state(audit_root)
        ctx["required_phases"] = [
            name for name, p in state.phases.items() if p.status != PHASE_SKIPPED
        ] or ["L1", "L2", "L3", "L4", "L5", "L6", "L6b", "L6c", "L7"]
        # Pass audit-state itself as semantic data for terminal-phase check
        semantic_data["mini-audit/audit-state.json"] = state.to_dict()
    except (StateTransitionError, AtomicIOError):
        pass

    # Pre-load JSON parseable artifacts for semantic checks. We do this
    # AFTER the runner so that file-existence is reported by the runner
    # (not masked by a pre-parse error here).
    result = runner.run(gate_def, semantic_data={}, ctx=ctx)

    # If existence checks already failed, don't bother loading semantics.
    if result.passed:
        for req in gate_def.required:
            if req.get("parse_json"):
                abs_path = req["path"] if os.path.isabs(req["path"]) else str(Path(args.workdir or ".") / req["path"])
                try:
                    semantic_data[req["path"]] = json.loads(Path(abs_path).read_text(encoding="utf-8"))
                except (FileNotFoundError, json.JSONDecodeError) as exc:
                    result.add_failure("parseability", req["path"], f"{type(exc).__name__}: {exc}")
        if semantic_data:
            # Re-run semantic checks with the data now loaded.
            from .gates import run_semantic  # local import to avoid cycle
            for check_name in gate_def.semantic_checks:
                ran_ok = False
                for src_path, src_data in semantic_data.items():
                    ok, msg = run_semantic(check_name, src_data, ctx)
                    if ok:
                        ran_ok = True
                        break
                if not ran_ok and semantic_data:
                    result.add_failure("semantic", None, f"semantic check {check_name!r} failed")

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
    except AtomicIOError as exc:
        _err(str(exc))
    ok, unresolved = ledger.audit_complete_ok()
    payload = {"ok": ok, "command": "coverage.validate",
               "histogram": ledger.histogram(),
               "unresolved": unresolved}
    _emit(payload, exit_code=0 if ok else 1)
    return 0 if ok else 1


def cmd_coverage_init(args: argparse.Namespace) -> int:
    """Initialize a coverage-ledger.json from a YAML/JSON plan."""
    audit_root = _resolve_audit_root(args)
    plan = json.loads(Path(args.plan).read_text(encoding="utf-8"))
    units = plan.get("units") or []
    ledger = CoverageLedger(audit_id=plan.get("audit_id", ""), units=[
        __import__("runtime.coverage", fromlist=["CoverageUnit"]).CoverageUnit.from_dict(u)
        for u in units
    ])
    ledger.save(audit_root / "coverage-ledger.json")
    _emit({"ok": True, "command": "coverage.init", "count": ledger.unit_count()})
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
    except (StateTransitionError, AtomicIOError, FindingValidationError, ValueError) as exc:
        _err(str(exc))
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())