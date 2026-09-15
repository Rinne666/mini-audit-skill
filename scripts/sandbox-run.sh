#!/usr/bin/env bash
# Run a command through the runtime's sandbox policy (Hardening v1.1 §8).
#
#   sandbox-check  →  capability PASS  →  sandbox-run  →  scanner / PoC
#
# There is NO host fallback. If the policy denies the requested kind, the
# command is not executed at all; this script exits 4 and prints the decision.
#
# Usage:
#   sandbox-run.sh --kind KIND [--audit-root PATH] [--timeout SECONDS] [--describe] -- CMD...
#
# --describe evaluates the policy and prints the decision without running
# anything (useful as a pre-flight).
#
# Exit codes:
#   0   command ran and succeeded
#   1   command ran and failed
#   4   sandbox policy blocked execution (nothing was run)
#   2   usage error
#
# This is a thin adapter over `mini-audit-runtime sandbox ...` so that the
# policy and the hard timeout have exactly one implementation (Python), and
# shell callers cannot accidentally bypass either.
set -euo pipefail

KIND="poc"
AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"
REPO_ROOT="${REPO_ROOT:-}"
TIMEOUT="300"
DESCRIBE=0
CMD=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kind)       KIND="${2:-}"; shift 2;;
    --audit-root) AUDIT_ROOT="${2:-}"; shift 2;;
    --repo-root)  REPO_ROOT="${2:-}"; shift 2;;
    --timeout)    TIMEOUT="${2:-}"; shift 2;;
    --describe)   DESCRIBE=1; shift;;
    --)           shift; CMD=("$@"); break;;
    -h|--help)
      cat <<'EOF'
Usage: sandbox-run.sh --kind KIND [--audit-root PATH] [--repo-root PATH]
                      [--timeout SECONDS] [--describe] -- CMD...
EOF
      exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -n "${MINI_AUDIT_RUNTIME:-}" ]]; then
  LAUNCHER="$MINI_AUDIT_RUNTIME"
else
  LAUNCHER="${SCRIPT_DIR}/mini-audit-runtime"
fi

if [[ ! -f "$LAUNCHER" ]]; then
  echo "sandbox-run.sh: cannot find the runtime launcher at $LAUNCHER" >&2
  echo "refusing to execute '$KIND' outside the sandbox policy" >&2
  exit 4
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ "$DESCRIBE" -eq 1 ]]; then
  "$PYTHON_BIN" "$LAUNCHER" sandbox check --kind "$KIND" --audit-root "$AUDIT_ROOT"
  exit $?
fi

if [[ ${#CMD[@]} -eq 0 ]]; then
  echo "sandbox-run.sh: no command given (use: -- CMD...)" >&2
  exit 2
fi

# NOTE: an empty array expanded as "${ARR[@]}" is an unbound-variable error under
# `set -u` in bash 3.2 (the /bin/bash shipped with macOS), so the two shapes are
# spelled out rather than conditionally spliced.
set +e
if [[ -n "$REPO_ROOT" ]]; then
  "$PYTHON_BIN" "$LAUNCHER" sandbox run \
    --kind "$KIND" --audit-root "$AUDIT_ROOT" --repo-root "$REPO_ROOT" \
    --timeout "$TIMEOUT" -- "${CMD[@]}"
else
  "$PYTHON_BIN" "$LAUNCHER" sandbox run \
    --kind "$KIND" --audit-root "$AUDIT_ROOT" \
    --timeout "$TIMEOUT" -- "${CMD[@]}"
fi
rc=$?
set -e

if [[ "$rc" -ne 0 ]]; then
  # Distinguish "blocked" (nothing ran) from "ran but failed".
  if "$PYTHON_BIN" "$LAUNCHER" sandbox check --kind "$KIND" --audit-root "$AUDIT_ROOT" >/dev/null 2>&1; then
    exit 1
  fi
  exit 4
fi
exit 0
