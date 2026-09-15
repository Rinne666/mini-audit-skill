#!/usr/bin/env bash
# Sandbox availability probe (Spec §25). Returns non-zero if the runtime
# is missing critical isolation capabilities required to execute
# target-controlled code (PoC executors).
#
# Usage:
#   sandbox-check.sh [--strict] [--audit-root PATH]
#
# Always writes JSON to mini-audit/sandbox/probe.json (or AUDIT_ROOT/sandbox/probe.json).
# Exit code: 0 if all critical capabilities present, 1 otherwise.
# With --strict, also fails on warnings.
#
# Hardening v1.1 §7: probing lives entirely in Python. v1.0's exit-code
# heredoc called sys.exit without importing sys, so the script always crashed
# after writing the probe. The verdict is now computed once, printed, and
# used as the exit status.
set -euo pipefail

STRICT=0
AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict) STRICT=1; shift;;
    --audit-root) AUDIT_ROOT="${2:-}"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage: sandbox-check.sh [--strict] [--audit-root PATH]

Writes sandbox capability probe as JSON.
Exit code: 0 if all critical capabilities present, 1 otherwise.
EOF
      exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

OUTPUT="${AUDIT_ROOT}/sandbox/probe.json"
mkdir -p "$(dirname "$OUTPUT")"

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 is required by sandbox-check.sh" >&2
  exit 3
fi

OUTPUT="$OUTPUT" STRICT="$STRICT" "$PYTHON_BIN" - <<'PYEOF'
"""Probe sandbox capabilities, write probe.json, and decide the exit code."""
import json
import os
import shutil
import sys
from pathlib import Path

OUTPUT = Path(os.environ["OUTPUT"])
STRICT = os.environ.get("STRICT") == "1"


def has_binary(*names):
    return any(shutil.which(n) is not None for n in names)


def has_env(name):
    return bool(os.environ.get(name))


checks = {
    "sandbox_available": has_env("MINI_AUDIT_SANDBOX") or has_binary("bwrap", "docker"),
    "external_network_disabled": has_env("MINI_AUDIT_NO_NET"),
    "safe_writable_scratch": os.access(
        os.environ.get("SCRATCH", os.environ.get("TMPDIR", "/tmp")), os.W_OK
    ),
    "timeout_available": has_binary("timeout", "gtimeout"),
    "resource_limit_available": has_binary("prlimit"),
    "environment_sanitized": has_env("MINI_AUDIT_SANITIZED"),
}

critical = ["sandbox_available", "safe_writable_scratch", "timeout_available"]
missing_critical = [k for k in critical if not checks[k]]
warnings = sorted(k for k, v in checks.items() if not v)

probe = {
    "schema_version": 1,
    "strict": STRICT,
    "checks": checks,
    "critical": critical,
    "missing_critical": missing_critical,
    "warnings": warnings,
    "verdict": "ok" if not missing_critical else "blocked",
}

OUTPUT.write_text(json.dumps(probe, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print(json.dumps({"verdict": probe["verdict"], "missing_critical": missing_critical,
                  "warnings": warnings}))

if missing_critical:
    sys.exit(1)
if STRICT and warnings:
    sys.exit(1)
sys.exit(0)
PYEOF

echo "wrote $OUTPUT" >&2
