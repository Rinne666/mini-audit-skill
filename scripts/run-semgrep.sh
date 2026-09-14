#!/usr/bin/env bash
# Run Semgrep and emit SARIF (Spec §26). Caller normalizes via the runtime CLI.
#
# Usage:
#   run-semgrep.sh --repo-root PATH [--config CONFIG] [--output PATH]
#
# Defaults:
#   --config p/security-audit p/owasp-top-ten
#   --output  mini-audit/scanner/semgrep.sarif
set -euo pipefail

REPO_ROOT=""
CONFIG="p/security-audit p/owasp-top-ten"
OUTPUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) REPO_ROOT="$2"; shift 2;;
    --config)    CONFIG="$2"; shift 2;;
    --output)    OUTPUT="$2"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage: run-semgrep.sh --repo-root PATH [--config CONFIG] [--output PATH]
EOF
      exit 0;;
    *)
      echo "unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$REPO_ROOT" ]]; then
  echo "--repo-root is required" >&2; exit 2
fi

if ! command -v semgrep >/dev/null 2>&1; then
  echo "semgrep not on PATH; please install (pip install semgrep)" >&2
  exit 3
fi

if [[ -z "$OUTPUT" ]]; then
  OUTPUT="mini-audit/scanner/semgrep.sarif"
fi

mkdir -p "$(dirname "$OUTPUT")"

# shellcheck disable=SC2086
semgrep \
  --config="$CONFIG" \
  --sarif \
  --output "$OUTPUT" \
  --error \
  --quiet \
  "$REPO_ROOT"

echo "wrote $OUTPUT" >&2