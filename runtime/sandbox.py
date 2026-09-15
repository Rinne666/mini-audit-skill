"""Sandbox policy (Spec §25, Hardening v1.1 §8).

CodeQL database creation, PoC execution, and anything else that runs
*target-controlled* code must not execute on the bare host. The runtime
enforces a single pipeline::

    sandbox-check  →  capability PASS  →  sandbox-run  →  scanner / PoC

When a critical capability is missing the runtime reports

    execution_status = blocked
    verdict          = needs_validation

and **refuses to fall back to direct host execution**. v1 documented this
policy but nothing executed it; the scripts still shelled out to
``codeql database create`` / PoC runners unconditionally.

The probe artifact is produced by ``scripts/sandbox-check.sh`` and read from
``<audit-root>/sandbox/probe.json``.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

from .scheduler import CommandOutcome, run_command_with_timeout

DEFAULT_AUDIT_ROOT = "mini-audit"

# Execution classes, ordered by how much they touch the target.
#
#   source-scan   read-only analysis of source text (Semgrep, Gitleaks, …).
#                 No target code runs, so a sandbox is not required — but the
#                 process still needs a writable scratch and a hard timeout.
#   target-build  something builds, resolves, or compiles the target
#                 (CodeQL `database create`, `npm install`, …). Requires
#                 isolation: build scripts are target-controlled.
#   poc           a proof-of-concept against a local instance. Must be
#                 network-isolated and resource-bounded.
#   target        arbitrary target-controlled execution: everything.
KIND_SOURCE_SCAN = "source-scan"
KIND_TARGET_BUILD = "target-build"
KIND_POC = "poc"
KIND_TARGET = "target"

# Backwards-friendly alias used in earlier docs.
KIND_SCANNER = KIND_TARGET_BUILD

EXECUTION_KINDS = (KIND_SOURCE_SCAN, KIND_TARGET_BUILD, KIND_POC, KIND_TARGET)

# Which probe checks are non-negotiable per kind.
#
# Note on `timeout_available`: the probe reports whether an external
# `timeout`/`gtimeout` binary exists, but the runtime does not depend on one —
# `scheduler.run_command_with_timeout` enforces the deadline itself via
# process-group SIGTERM/SIGKILL. So a missing external binary is a *warning*,
# not a blocker, and hard timeouts are always available.
CRITICAL_CHECKS: dict[str, tuple[str, ...]] = {
    KIND_SOURCE_SCAN: (
        "safe_writable_scratch",
    ),
    KIND_TARGET_BUILD: (
        "sandbox_available",
        "safe_writable_scratch",
    ),
    KIND_POC: (
        "sandbox_available",
        "external_network_disabled",
        "safe_writable_scratch",
        "resource_limit_available",
    ),
    KIND_TARGET: (
        "sandbox_available",
        "external_network_disabled",
        "safe_writable_scratch",
        "resource_limit_available",
        "environment_sanitized",
    ),
}


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
    def reason(self) -> str:
        if self.ok:
            return f"sandbox capabilities satisfied for {self.kind}"
        if not self.probe_present:
            return (
                f"sandbox probe not found ({self.probe_path}); run scripts/sandbox-check.sh "
                f"before {self.kind} execution"
            )
        return (
            f"missing critical sandbox capabilities for {self.kind}: "
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
            "host_fallback": False,
            "hard_timeout_enforced_by_runtime": True,
        }


def probe_file(audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT) -> Path:
    return Path(audit_root) / "sandbox" / "probe.json"


def read_probe(audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT) -> Optional[dict[str, Any]]:
    path = probe_file(audit_root)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def evaluate_probe(probe: Optional[Mapping[str, Any]], kind: str,
                   *, audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT) -> SandboxDecision:
    """Turn a probe document into a go/no-go decision for *kind*."""
    if kind not in EXECUTION_KINDS:
        raise ValueError(f"unknown execution kind {kind!r}; expected one of {EXECUTION_KINDS}")
    path = probe_file(audit_root)
    if probe is None:
        return SandboxDecision(ok=False, kind=kind, probe_path=str(path), probe_present=False)

    raw_checks = probe.get("checks") or {}
    if not isinstance(raw_checks, Mapping):
        raw_checks = {}
    checks = {str(k): bool(v) for k, v in raw_checks.items()}
    critical = CRITICAL_CHECKS[kind]
    missing = [c for c in critical if not checks.get(c, False)]
    warnings = sorted(k for k, v in checks.items() if not v and k not in missing)
    return SandboxDecision(
        ok=not missing,
        kind=kind,
        missing_critical=missing,
        warnings=warnings,
        checks=checks,
        probe_path=str(path),
        probe_present=True,
    )


def check_sandbox(kind: str = KIND_POC,
                  audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT,
                  *, probe: Optional[Mapping[str, Any]] = None) -> SandboxDecision:
    """Evaluate the current sandbox probe for *kind*."""
    if probe is None:
        probe = read_probe(audit_root)
    return evaluate_probe(probe, kind, audit_root=audit_root)


def run_sandboxed(
    argv: Sequence[str],
    *,
    kind: str = KIND_POC,
    audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT,
    timeout_seconds: float = 300,
    cwd: Optional[os.PathLike[str] | str] = None,
    env: Optional[Mapping[str, str]] = None,
    probe: Optional[Mapping[str, Any]] = None,
    grace_seconds: float = 5.0,
) -> "SandboxRunResult":
    """Run *argv* only if the sandbox policy allows *kind*.

    There is no host fallback. A blocked request returns without executing
    anything, with ``execution_status="blocked"`` and
    ``verdict="needs_validation"``.
    """
    decision = check_sandbox(kind, audit_root, probe=probe)
    if not decision.ok:
        return SandboxRunResult(decision=decision, executed=False, outcome=None)
    outcome = run_command_with_timeout(
        argv, timeout_seconds=timeout_seconds, cwd=cwd, env=env, grace_seconds=grace_seconds
    )
    return SandboxRunResult(decision=decision, executed=True, outcome=outcome)


@dataclasses.dataclass
class SandboxRunResult:
    decision: SandboxDecision
    executed: bool
    outcome: Optional[CommandOutcome]

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "ok": self.executed and bool(self.outcome and self.outcome.returncode == 0),
            "executed": self.executed,
            "sandbox": self.decision.to_dict(),
        }
        if self.outcome is not None:
            payload["outcome"] = self.outcome.to_dict()
        return payload


def run_probe_script(audit_root: os.PathLike[str] | str = DEFAULT_AUDIT_ROOT,
                     *, script: Optional[os.PathLike[str] | str] = None,
                     strict: bool = False,
                     timeout_seconds: float = 60) -> SandboxDecision:
    """Invoke ``scripts/sandbox-check.sh`` and evaluate the resulting probe.

    The probe script itself is the only thing we run on the host here: it
    merely inspects availability and writes JSON. It executes no target code.
    """
    if script is None:
        script = Path(__file__).resolve().parent.parent / "scripts" / "sandbox-check.sh"
    argv = ["bash", str(script), "--audit-root", str(audit_root)]
    if strict:
        argv.append("--strict")
    outcome = run_command_with_timeout(argv, timeout_seconds=timeout_seconds)
    probe = read_probe(audit_root)
    if probe is None:
        decision = evaluate_probe(None, KIND_POC, audit_root=audit_root)
        decision.warnings.append(f"sandbox-check.sh exit={outcome.returncode}: {outcome.stderr.strip()[:200]}")
        return decision
    decision = evaluate_probe(probe, KIND_POC, audit_root=audit_root)
    if outcome.returncode not in (0, 1):
        decision.warnings.append(f"sandbox-check.sh exited {outcome.returncode}")
    return decision
