#!/usr/bin/env bash
# Sandbox verification probe (Spec §25, Hardening v1.1 §8, v1.1.1 §2).
#
#   sandbox-check  →  verify a concrete backend by canary  →  write probe.json
#
# There is NO host fallback and no self-declared capability. Earlier versions
# probed `MINI_AUDIT_SANDBOX=1` / "does bwrap exist?" and called that a sandbox;
# that only proved someone said so. Every backend is now exercised with a
# differential canary and the probe records what was *demonstrated*.
#
# Usage:
#   sandbox-check.sh [--strict] [--audit-root PATH] [--repo-root PATH] [--kind KIND]
#
# Writes <AUDIT_ROOT>/sandbox/probe.json.
# Exit code: 0 if a backend demonstrably satisfies KIND, 1 otherwise.

set -euo pipefail

STRICT=0
AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"
REPO_ROOT="${REPO_ROOT:-.}"
KIND="${KIND:-poc}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict) STRICT=1; shift;;
    --audit-root) AUDIT_ROOT="${2:-}"; shift 2;;
    --repo-root)  REPO_ROOT="${2:-}"; shift 2;;
    --kind)       KIND="${2:-}"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage: sandbox-check.sh [--strict] [--audit-root PATH] [--repo-root PATH] [--kind KIND]

Verifies isolation backends with a differential canary and writes
<AUDIT_ROOT>/sandbox/probe.json. Exit code: 0 if a backend demonstrably
satisfies KIND, 1 otherwise.
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
  echo "sandbox-check.sh: cannot find the runtime launcher at $LAUNCHER" >&2
  exit 3
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 is required by sandbox-check.sh" >&2
  exit 3
fi

# Delegate to the runtime: the canary harness, the control vocabulary, and the
# decision all live in one place (runtime/sandbox_backend.py) so the shell cannot
# drift from Python.
OUT="${TMPDIR:-/tmp}/mini-audit-sandbox-probe.json"
set +e
"$PYTHON_BIN" "$LAUNCHER" sandbox probe \
  --kind "$KIND" --audit-root "$AUDIT_ROOT" --repo-root "$REPO_ROOT" \
  > "$OUT"
rc=$?
set -e

echo "wrote ${AUDIT_ROOT}/sandbox/probe.json" >&2

if [[ "$rc" -ne 0 ]]; then
  echo "sandbox verification failed for kind '$KIND' (no backend demonstrated the required controls)" >&2
  if [[ "$STRICT" -eq 1 ]]; then
    cat "$OUT" >&2 || true
  fi
fi
exit "$rc"
