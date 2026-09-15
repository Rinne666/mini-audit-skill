#!/usr/bin/env bash
# Run Semgrep and emit SARIF (Spec §26). Caller normalizes via the runtime CLI.
#
# Usage:
#   run-semgrep.sh --repo-root PATH [--config CONFIG]... [--output PATH]
#
# Defaults:
#   --config p/security-audit --config p/owasp-top-ten
#   --output  mini-audit/scanner/semgrep.sarif
#
# Hardening v1.1 §7: each registry config is passed as its own `--config`
# argument. v1.0 did `--config="p/security-audit p/owasp-top-ten"`, i.e. a
# single string containing a space, which Semgrep interprets as one bogus
# ruleset path. `--config` may now be repeated.
set -euo pipefail

REPO_ROOT=""
OUTPUT=""
CONFIGS=()
AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) REPO_ROOT="${2:-}"; shift 2;;
    --config)
      # Allow either one config per flag, or a "a b" list in one flag.
      # shellcheck disable=SC2206
      CONFIGS+=( ${2:-} ); shift 2;;
    --output)    OUTPUT="${2:-}"; shift 2;;
    --audit-root) AUDIT_ROOT="${2:-}"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage: run-semgrep.sh --repo-root PATH [--config CONFIG]... [--output PATH]

--config may be repeated. Defaults to --config p/security-audit
--config p/owasp-top-ten.
EOF
      exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$REPO_ROOT" ]]; then
  echo "--repo-root is required" >&2; exit 2
fi

if [[ ${#CONFIGS[@]} -eq 0 ]]; then
  CONFIGS=("p/security-audit" "p/owasp-top-ten")
fi

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep not on PATH; please install (pip install semgrep)" >&2
  exit 3
fi

if [[ -z "$OUTPUT" ]]; then
  OUTPUT="${AUDIT_ROOT}/scanner/semgrep.sarif"
fi

mkdir -p "$(dirname "$OUTPUT")"

# Build `--config <c>` for every configured ruleset.
CONFIG_ARGS=()
for c in "${CONFIGS[@]}"; do
  CONFIG_ARGS+=(--config "$c")
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# NOTE: `--error` is deliberately NOT passed. It makes Semgrep exit non-zero
# whenever it finds anything, which this wrapper (and the agents that call it)
# would have to read as "the scan failed" — right on the one run that mattered.
# The SARIF is the source of truth for findings (runtime/sarif.py normalizes
# it); this script's exit code reports scan health only:
#   0  scan completed and the SARIF was written
#   1  the scanner ran but errored
#   4  the sandbox policy blocked execution (nothing ran)
#
# Hardening v1.1 §8: scanner execution goes through the sandbox policy.
# Semgrep only reads source text, so the `source-scan` kind is enough — but the
# invocation still runs the check-first pipeline rather than exec'ing directly,
# so a policy change (e.g. requiring isolation for a hostile ruleset) applies
# here too without touching this script.
set +e
if [[ -x "${SCRIPT_DIR}/sandbox-run.sh" ]]; then
  "${SCRIPT_DIR}/sandbox-run.sh" --kind source-scan --audit-root "${AUDIT_ROOT}" -- \
    semgrep "${CONFIG_ARGS[@]}" --sarif --output "$OUTPUT" --quiet "$REPO_ROOT"
  rc=$?
else
  echo "warning: sandbox-run.sh missing; running semgrep without the sandbox policy" >&2
  semgrep "${CONFIG_ARGS[@]}" --sarif --output "$OUTPUT" --quiet "$REPO_ROOT"
  rc=$?
fi
set -e

if [[ "$rc" -eq 4 ]]; then
  echo "semgrep blocked by the sandbox policy; no scan was performed" >&2
  exit 4
fi

if [[ "$rc" -ne 0 ]]; then
  # sandbox-run.sh reports 1 for "ran but failed"; the scanner's own exit code
  # and stderr are preserved in the sandbox.run JSON on stdout.
  echo "semgrep did not produce a usable SARIF (sandbox-run exit $rc)" >&2
  exit 1
fi

if [[ ! -s "$OUTPUT" ]]; then
  echo "semgrep reported success but wrote no SARIF to $OUTPUT" >&2
  exit 1
fi

echo "wrote $OUTPUT" >&2
