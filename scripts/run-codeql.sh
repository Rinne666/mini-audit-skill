#!/usr/bin/env bash
# Run CodeQL and emit SARIF (Spec §26).
#
# Usage:
#   run-codeql.sh --repo-root PATH --language LANG [--database DIR] [--output PATH]
#                 [--kind source-scan|target-build|poc|target] [--allow-host-fallback]
#
# Default database: mini-audit/scanner/codeql-db
# Default output:   mini-audit/scanner/codeql.sarif
#
# Hardening v1.1 §8: `codeql database create` builds/compiles the target, i.e.
# it executes target-controlled build scripts. It therefore goes through the
# sandbox policy (kind `target-build` by default) instead of running on the
# bare host. When the required sandbox capabilities are missing the script
# does NOT run CodeQL and does NOT degrade to host execution: it writes a
# blocked marker and exits 4, leaving the caller to record
# execution_status=blocked / verdict=needs_validation.
set -euo pipefail

REPO_ROOT=""
LANGUAGE=""
DATABASE=""
OUTPUT=""
KIND="target-build"
AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) REPO_ROOT="${2:-}"; shift 2;;
    --language)  LANGUAGE="${2:-}"; shift 2;;
    --database)  DATABASE="${2:-}"; shift 2;;
    --output)    OUTPUT="${2:-}"; shift 2;;
    --kind)      KIND="${2:-}"; shift 2;;
    --audit-root) AUDIT_ROOT="${2:-}"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage: run-codeql.sh --repo-root PATH --language LANG [--database DIR] [--output PATH]
                     [--kind KIND] [--audit-root PATH]

Runs CodeQL under the sandbox policy. Produces SARIF or a blocked marker.
Exit codes: 0 ok, 2 usage, 3 codeql missing, 4 sandbox blocked.
EOF
      exit 0;;
    *) echo "unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$REPO_ROOT" || -z "$LANGUAGE" ]]; then
  echo "--repo-root and --language are required" >&2; exit 2
fi

DATABASE="${DATABASE:-${AUDIT_ROOT}/scanner/codeql-db}"
OUTPUT="${OUTPUT:-${AUDIT_ROOT}/scanner/codeql.sarif}"
BLOCKED_MARKER="${AUDIT_ROOT}/scanner/codeql-blocked.json"
mkdir -p "$(dirname "$DATABASE")" "$(dirname "$OUTPUT")"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SANDBOX_RUN="${SCRIPT_DIR}/sandbox-run.sh"

# stdout carries exactly ONE JSON document (a summary with the per-step reports
# nested under "steps"). Previously each step printed its own report, so the
# stream was three concatenated documents and `json.load(stdout)` raised
# "Extra data". run-semgrep.sh emits a single document; this matches it.
DESCRIBE_JSON="null"
CREATE_JSON="null"
ANALYZE_JSON="null"
SUMMARY_STATUS="blocked"
SUMMARY_VERDICT="null"
SUMMARY_REASON=""

emit_summary() {
  cat <<EOF
{
  "schema_version": 1,
  "scanner": "codeql",
  "kind": "$KIND",
  "output": "$OUTPUT",
  "database": "$DATABASE",
  "execution_status": "$SUMMARY_STATUS",
  "verdict": $SUMMARY_VERDICT,
  "reason": "$SUMMARY_REASON",
  "host_fallback": false,
  "hard_timeout_enforced_by_runtime": true,
  "steps": [$DESCRIBE_JSON, $CREATE_JSON, $ANALYZE_JSON]
}
EOF
}

# 1. sandbox-check → capability decision. No host fallback, ever.
if [[ ! -x "$SANDBOX_RUN" ]]; then
  echo "missing $SANDBOX_RUN; refusing to run CodeQL outside the sandbox policy" >&2
  exit 4
fi

set +e
DESCRIBE_JSON="$("$SANDBOX_RUN" --kind "$KIND" --audit-root "$AUDIT_ROOT" --describe)"
describe_rc=$?
set -e

if [[ "$describe_rc" -ne 0 ]]; then
  cat >"$BLOCKED_MARKER" <<EOF
{
  "schema_version": 1,
  "scanner": "codeql",
  "kind": "$KIND",
  "execution_status": "blocked",
  "verdict": "needs_validation",
  "reason": "sandbox policy did not grant the capabilities required for '$KIND'",
  "host_fallback": false
}
EOF
  SUMMARY_REASON="sandbox policy did not grant the capabilities required for '$KIND'"
  SUMMARY_VERDICT='"needs_validation"'
  emit_summary
  echo "sandbox blocked: CodeQL not executed; wrote $BLOCKED_MARKER" >&2
  exit 4
fi

if ! command -v codeql >/dev/null 2>&1; then
  echo "codeql not on PATH; please install the CodeQL CLI" >&2
  exit 3
fi

# 2. sandbox-run → scanner. The build and the analysis both go through the
#    policy-enforcing wrapper.
#
#    Exit codes mirror run-semgrep.sh so callers see one contract:
#      0  analysis completed and the SARIF was written
#      1  the scanner ran but failed (the sandbox.run report has the detail)
#      4  the sandbox policy blocked execution (nothing ran)
#    Without the explicit handling below, `set -e` turned any failure into a
#    mute non-zero exit with no indication of which step broke.
SUMMARY_STATUS="allowed"
SUMMARY_REASON="codeql database create + analyze completed"
set +e
CREATE_JSON="$("$SANDBOX_RUN" --kind "$KIND" --audit-root "$AUDIT_ROOT" -- \
  codeql database create "$DATABASE" --language="$LANGUAGE" --source-root="$REPO_ROOT" --overwrite)"
rc=$?
if [[ "$rc" -eq 0 ]]; then
  ANALYZE_JSON="$("$SANDBOX_RUN" --kind "$KIND" --audit-root "$AUDIT_ROOT" -- \
    codeql database analyze "$DATABASE" --format=sarif-latest --output="$OUTPUT")"
  rc=$?
fi
set -e

if [[ "$rc" -eq 4 ]]; then
  SUMMARY_STATUS="blocked"
  SUMMARY_VERDICT='"needs_validation"'
  SUMMARY_REASON="sandbox policy blocked the CodeQL invocation"
  emit_summary
  echo "CodeQL blocked by the sandbox policy; nothing was run" >&2
  exit 4
fi

if [[ "$rc" -ne 0 ]]; then
  SUMMARY_STATUS="failed"
  SUMMARY_REASON="CodeQL did not produce a usable SARIF (sandbox-run exit $rc)"
  emit_summary
  echo "CodeQL did not produce a usable SARIF (sandbox-run exit $rc)" >&2
  exit 1
fi

if [[ ! -s "$OUTPUT" ]]; then
  SUMMARY_STATUS="failed"
  SUMMARY_REASON="CodeQL reported success but wrote no SARIF"
  emit_summary
  echo "CodeQL reported success but wrote no SARIF to $OUTPUT" >&2
  exit 1
fi

emit_summary
echo "wrote $OUTPUT" >&2
