"""Sandbox policy (Spec §25, Hardening v1.1 §8, v1.1.1 §2).

CodeQL database creation, PoC execution, and anything else that runs
*target-controlled* code must not execute on the bare host. The runtime
enforces a single pipeline::

    sandbox-check  →  select a *verified* backend  →  wrap the argv
                   →  execute inside the wrapper
                   →  no verified backend ⇒ blocked

Hardening v1.1 executed the policy's *decision* but not its *intent*: once the
probe said the host had a sandbox, the command ran under plain ``subprocess`` on
the host, and "has docker installed" was treated as "is sandboxed". v1.1.1 fixes
that by requiring a backend that has **demonstrated** the needed controls with a
differential canary (see :mod:`runtime.sandbox_backend`). Controls are never
inferred from a binary's presence or from a self-declared environment variable.

When the requirement cannot be met the runtime reports::

    execution_status = blocked
    verdict          = needs_validation

and **refuses to fall back to direct host execution**.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from .process_control import CommandOutcome, run_command_with_timeout
from .sandbox_backend import (
    ALL_CONTROLS,
    BACKENDS,
    CONTROL_ENV_SANITIZED,
    CONTROL_HARD_TIMEOUT,
    CONTROL_NETWORK_DENIAL,
    CONTROL_READ_ONLY_SOURCE,
    CONTROL_RESOURCE_LIMITS,
    CONTROL_WRITE_CONFINEMENT,
    IsolationBackend,
    SandboxSpec,
    sanitized_env,
    verify_backend,
)

DEFAULT_AUDIT_ROOT = "mini-audit"
PROBE_SCHEMA_VERSION = 2

# Execution classes, ordered by how much they touch the target.
#
#   source-scan   read-only analysis of source text (Semgrep, Gitleaks, …).
#                 No target code runs, so network reachability is permitted
#                 (a ruleset may be fetched) but the source tree stays
#                 read-only and writes stay confined to scratch.
#   target-build  something builds, resolves, or compiles the target
#                 (CodeQL `database create`, `npm install`, …). Build scripts
#                 are target-controlled, so network is denied.
#   poc           a proof-of-concept against a local instance: network-isolated
#                 and resource-bounded.
#   target        arbitrary target-controlled execution: everything.
KIND_SOURCE_SCAN = "source-scan"
KIND_TARGET_BUILD = "target-build"
KIND_POC = "poc"
KIND_TARGET = "target"

# Backwards-friendly alias used in earlier docs.
KIND_SCANNER = KIND_TARGET_BUILD

EXECUTION_KINDS = (KIND_SOURCE_SCAN, KIND_TARGET_BUILD, KIND_POC, KIND_TARGET)

# Which controls a kind actually depends on. This table — not the probe — is the
# authority; a probe can only report what a backend demonstrated.
#
# `hard_timeout` is enforced by the process_control process-group deadline and is
# always available (see `runtime.process_control`), but it is listed explicitly so the
# requirement is visible where the policy is read.
REQUIRED_CONTROLS: dict[str, tuple[str, ...]] = {
    KIND_SOURCE_SCAN: (
        CONTROL_READ_ONLY_SOURCE,
        CONTROL_WRITE_CONFINEMENT,
        CONTROL_HARD_TIMEOUT,
    ),
    KIND_TARGET_BUILD: (
        CONTROL_READ_ONLY_SOURCE,
        CONTROL_WRITE_CONFINEMENT,
        CONTROL_NETWORK_DENIAL,
        CONTROL_HARD_TIMEOUT,
    ),
    KIND_POC: (
        CONTROL_READ_ONLY_SOURCE,
        CONTROL_WRITE_CONFINEMENT,
        CONTROL_NETWORK_DENIAL,
        CONTROL_RESOURCE_LIMITS,
        CONTROL_HARD_TIMEOUT,
    ),
    KIND_TARGET: (
        CONTROL_READ_ONLY_SOURCE,
        CONTROL_WRITE_CONFINEMENT,
        CONTROL_NETWORK_DENIAL,
        CONTROL_RESOURCE_LIMITS,
        CONTROL_ENV_SANITIZED,
        CONTROL_HARD_TIMEOUT,
    ),
}

# Retained for callers that just want the tuple; the semantics changed from
# "capability flags in a probe" to "controls a backend must demonstrate".
CRITICAL_CHECKS = REQUIRED_CONTROLS


class SandboxBlocked(RuntimeError):
    """Raised when execution is requested without the required capabilities."""

    def __init__(self, decision: "SandboxDecision") -> None:
        self.decision = decision
        super().__init__(decision.reason)


@dataclasses.dataclass
class SandboxDecision:
    """Verdict for one execution request."""

    ok: bool
    kind: str
    missing_critical: list[str] = dataclasses.field(default_factory=list)
    warnings: list[str] = dataclasses.field(default_factory=list)
    checks: dict[str, bool] = dataclasses.field(default_factory=dict)
    probe_path: Optional[str] = None
    probe_present: bool = False
    # v1.1.1 — which concrete backend will contain this execution, and what it
    # demonstrated. `isolation_backend is None` means "nothing will contain it",
    # which is only ever allowed when `ok` is False.
    isolation_backend: Optional[str] = None
    controls: dict[str, bool] = dataclasses.field(default_factory=dict)
    legacy_probe: bool = False
    reason_override: Optional[str] = None

    @property
    def execution_status(self) -> str:
        return "allowed" if self.ok else "blocked"

    @property
    def verdict(self) -> Optional[str]:
        # A blocked execution cannot be confirmed — it can only be escalated
        # for validation. Never "rejected": absence of sandbox is not evidence
        # of absence of the bug.
        return None if self.ok else "needs_validation"

    @property
    def isolation_verified(self) -> bool:
        return bool(self.ok and self.isolation_backend)

    @property
    def reason(self) -> str:
        if self.ok:
            controls = ", ".join(sorted(k for k, v in self.controls.items() if v))
            return f"{self.kind} admitted via {self.isolation_backend} ({controls})"
        if self.reason_override:
            return self.reason_override
        if not self.probe_present:
            return (
                f"sandbox probe not found ({self.probe_path}); run scripts/sandbox-check.sh "
                f"before {self.kind} execution"
            )
        if self.legacy_probe:
            return (
                "sandbox probe is the legacy capability-only format (schema_version 1), "
                "which only records what the host *claims*; re-run scripts/sandbox-check.sh "
                "to produce a verified-backend probe"
            )
        return (
            f"no isolation backend demonstrated the controls required by {self.kind}: "
            f"{', '.join(self.missing_critical)}"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "kind": self.kind,
            "execution_status": self.execution_status,
            "verdict": self.verdict,
            "reason": self.reason,
            "missing_critical": list(self.missing_critical),
            "warnings": list(self.warnings),
            "checks": dict(self.checks),
            "probe_present": self.probe_present,
            "probe_path": self.probe_path,
            "isolation_backend": self.isolation_backend,
            "isolation_verified": self.isolation_verified,
            "controls": dict(self.controls),
            "host_fallback": False,
            "hard_timeout_enforced_by_runtime": True,
        }


def probe_file(audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT) -> Path:
    return Path(audit_root) / "sandbox" / "probe.json"


def read_probe(audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT) -> Optional[dict[str, Any]]:
    path = probe_file(audit_root)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def write_probe(audit_root: os.PathLike[str] | str, probe: Mapping[str, Any]) -> Path:
    path = probe_file(audit_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(probe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def probe_document(kind: str = KIND_POC, *, repo_root: os.PathLike[str] | str = ".",
                   audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT,
                   base_env: Optional[Mapping[str, str]] = None,
                   timeout_seconds: float = 45.0) -> dict[str, Any]:
    """Verify every available backend and return the probe document.

    Each backend is verified independently (with its own differential canary),
    so the document records *evidence*, not a claim. Backends blocked on an
    unavailable binary/daemon/image are recorded with ``usable=False`` and the
    reason, which is what makes "why isn't CodeQL running?" answerable.
    """
    spec = SandboxSpec.for_kind(
        kind, repo_root=repo_root, audit_root=audit_root, base_env=base_env or dict(os.environ),
    )
    reports = []
    for backend in BACKENDS:
        if not backend.available():
            reports.append({
                "backend": backend.name,
                "usable": False,
                "verified": False,
                "controls": {c: False for c in ALL_CONTROLS},
                "demonstrated": [],
                "evidence": {},
                "detail": backend.unavailable_reason(),
                "image": getattr(backend, "image", "") or "",
            })
            continue
        reports.append(verify_backend(backend, spec, timeout_seconds=timeout_seconds).to_dict())

    return {
        "schema_version": PROBE_SCHEMA_VERSION,
        "kind": kind,
        "repo_root": str(Path(repo_root).resolve()),
        "audit_root": str(Path(audit_root).resolve()),
        "backends": reports,
        "note": (
            "Each backend is verified with a differential canary (the probe runs with and "
            "without the wrapper; a control counts only if the unisolated run performed the "
            "forbidden action and the isolated run did not). Presence of a binary is not "
            "evidence of containment."
        ),
    }


def evaluate_probe(probe: Optional[Mapping[str, Any]], kind: str,
                   *, audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT) -> SandboxDecision:
    """Turn a probe document into a go/no-go decision for *kind*."""
    if kind not in EXECUTION_KINDS:
        raise ValueError(f"unknown execution kind {kind!r}; expected one of {EXECUTION_KINDS}")
    path = probe_file(audit_root)
    required = REQUIRED_CONTROLS[kind]

    if probe is None:
        return SandboxDecision(ok=False, kind=kind, probe_path=str(path), probe_present=False)

    if not isinstance(probe.get("backends"), list):
        # A capability-only probe. It cannot establish containment — the whole
        # point of v1.1.1 — so it fails closed instead of being interpreted.
        return SandboxDecision(
            ok=False, kind=kind, probe_path=str(path), probe_present=True,
            legacy_probe=True, missing_critical=list(required),
        )

    reports = [r for r in probe["backends"] if isinstance(r, Mapping)]
    usable = [r for r in reports if r.get("usable")]

    if not usable:
        detail = "; ".join(
            f"{r.get('backend')}: {r.get('detail') or 'unusable'}" for r in reports
        ) or "no backends were probed"
        return SandboxDecision(
            ok=False, kind=kind, probe_path=str(path), probe_present=True,
            missing_critical=list(required),
            reason_override=f"no usable isolation backend on this host — {detail}",
        )

    best: Optional[tuple[Mapping[str, Any], list[str]]] = None
    for report in usable:
        controls = report.get("controls") or {}
        missing = [c for c in required if not controls.get(c)]
        if not missing:
            best = (report, [])
            break
        if best is None or len(missing) < len(best[1]):
            best = (report, missing)

    assert best is not None
    report, missing = best
    controls = {str(k): bool(v) for k, v in (report.get("controls") or {}).items()}
    if missing:
        detail = "; ".join(
            f"{r.get('backend')}: missing {[c for c in required if not (r.get('controls') or {}).get(c)]}"
            for r in usable
        )
        return SandboxDecision(
            ok=False, kind=kind, probe_path=str(path), probe_present=True,
            missing_critical=missing, checks=controls,
            isolation_backend=str(report.get("backend")),
            reason_override=(
                f"no isolation backend demonstrated the controls required by {kind} "
                f"({', '.join(missing)}); {detail}"
            ),
        )

    return SandboxDecision(
        ok=True,
        kind=kind,
        missing_critical=[],
        warnings=sorted(k for k, v in controls.items() if not v and k not in required),
        checks=controls,
        probe_path=str(path),
        probe_present=True,
        isolation_backend=str(report.get("backend")),
        controls=controls,
    )


def check_sandbox(kind: str = KIND_POC,
                  audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT,
                  *, probe: Optional[Mapping[str, Any]] = None) -> SandboxDecision:
    """Evaluate the current sandbox probe for *kind*."""
    if probe is None:
        probe = read_probe(audit_root)
    return evaluate_probe(probe, kind, audit_root=audit_root)


def backend_by_name(name: str) -> Optional[IsolationBackend]:
    for backend in BACKENDS:
        if backend.name == name:
            return backend
    return None


def run_sandboxed(
    argv: Sequence[str],
    *,
    kind: str = KIND_POC,
    audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT,
    repo_root: Optional[os.PathLike[str] | str] = None,
    scratch_dir: Optional[os.PathLike[str] | str] = None,
    timeout_seconds: float = 300,
    cwd: Optional[os.PathLike[str] | str] = None,
    env: Optional[Mapping[str, str]] = None,
    probe: Optional[Mapping[str, Any]] = None,
    grace_seconds: float = 5.0,
    backend: Optional[IsolationBackend] = None,
) -> "SandboxRunResult":
    """Run *argv* only inside a verified isolation backend.

    There is no host fallback: a blocked request returns without executing
    anything, with ``execution_status="blocked"`` and
    ``verdict="needs_validation"``. When the probe admits the run, the command is
    executed **inside the wrapper** — the isolation is not advisory.
    """
    decision = check_sandbox(kind, audit_root, probe=probe)
    if not decision.ok:
        return SandboxRunResult(decision=decision, executed=False, outcome=None)

    active = backend or backend_by_name(decision.isolation_backend or "")
    if active is None or not active.available():
        # The probe names a backend we cannot instantiate (removed since the
        # probe was written, different host, …). We cannot build a wrapper, so we
        # must not run.
        decision.ok = False
        decision.reason_override = (
            f"probe selected backend {decision.isolation_backend!r}, which is not "
            f"available now; re-run scripts/sandbox-check.sh"
        )
        return SandboxRunResult(decision=decision, executed=False, outcome=None)

    work = Path(cwd).resolve() if cwd else Path(repo_root or ".").resolve()
    spec = SandboxSpec.for_kind(
        kind,
        repo_root=repo_root or work,
        audit_root=audit_root,
        scratch_dir=scratch_dir,
        cwd=work,
        base_env=env if env is not None else dict(os.environ),
    )
    spec.scratch_dir.mkdir(parents=True, exist_ok=True)

    wrapped = active.build_argv(list(argv), spec)
    outcome = run_command_with_timeout(
        wrapped,
        timeout_seconds=timeout_seconds,
        cwd=work,
        env=sanitized_env(spec),
        grace_seconds=grace_seconds,
    )
    return SandboxRunResult(decision=decision, executed=True, outcome=outcome, argv=wrapped)


@dataclasses.dataclass
class SandboxRunResult:
    decision: SandboxDecision
    executed: bool
    outcome: Optional[CommandOutcome]
    argv: Optional[list[str]] = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.executed and bool(self.outcome and self.outcome.returncode == 0),
            "executed": self.executed,
            "sandbox": self.decision.to_dict(),
        }
        if self.outcome is not None:
            payload["outcome"] = self.outcome.to_dict()
        if self.argv is not None:
            payload["isolation_argv"] = list(self.argv)
        return payload


def run_probe_script(audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT,
                     *, script: Optional[os.PathLike[str] | str] = None,
                     strict: bool = False,
                     kind: str = KIND_POC,
                     timeout_seconds: float = 60) -> SandboxDecision:
    """Invoke ``scripts/sandbox-check.sh`` and evaluate the resulting probe.

    The probe script itself is the only thing we run on the host here: it
    inspects availability, runs the canaries, and writes JSON. It executes no
    target code.
    """
    if script is None:
        script = Path(__file__).resolve().parent.parent / "scripts" / "sandbox-check.sh"
    argv = ["bash", str(script), "--audit-root", str(audit_root), "--kind", kind]
    if strict:
        argv.append("--strict")
    outcome = run_command_with_timeout(argv, timeout_seconds=timeout_seconds)
    probe = read_probe(audit_root)
    if probe is None:
        decision = evaluate_probe(None, kind, audit_root=audit_root)
        decision.warnings.append(f"sandbox-check.sh exit={outcome.returncode}: {outcome.stderr.strip()[:200]}")
        return decision
    decision = evaluate_probe(probe, kind, audit_root=audit_root)
    if outcome.returncode not in (0, 1):
        decision.warnings.append(f"sandbox-check.sh exited {outcome.returncode}")
    return decision
