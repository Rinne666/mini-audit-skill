#!/usr/bin/env bash
# Run CodeQL and emit SARIF (Spec §26).
#
# Usage:
#   run-codeql.sh --repo-root PATH --language LANG [--database DIR] [--output PATH]
#
# Default database: mini-audit/scanner/codeql-db
# Default output:   mini-audit/scanner/codeql.sarif
set -euo pipefail

REPO_ROOT=""
LANGUAGE=""
DATABASE=""
OUTPUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-root) REPO_ROOT="$2"; shift 2;;
    --language)  LANGUAGE="$2"; shift 2;;
    --database)  DATABASE="$2"; shift 2;;
    --output)    OUTPUT="$2"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage: run-codeql.sh --repo-root PATH --language LANG [--database DIR] [--output PATH]
EOF
      exit 0;;
    *)
      echo "unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$REPO_ROOT" || -z "$LANGUAGE" ]]; then
  echo "--repo-root and --language are required" >&2; exit 2
fi

if ! command -v codeql >/dev/null 2>&1; then
  echo "codeql not on PATH; please install the CodeQL CLI" >&2
  exit 3
fi

DATABASE="${DATABASE:-mini-audit/scanner/codeql-db}"
OUTPUT="${OUTPUT:-mini-audit/scanner/codeql.sarif}"
mkdir -p "$(dirname "$DATABASE")" "$(dirname "$OUTPUT")"

codeql database create "$DATABASE" --language="$LANGUAGE" --source-root="$REPO_ROOT" --overwrite
codeql database analyze "$DATABASE" --format=sarif-latest --output="$OUTPUT"
codeql database bundle "$DATABASE" --output=/dev/null 2>/dev/null || true

echo "wrote $OUTPUT" >&2