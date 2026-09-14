#!/usr/bin/env bash
# Detect available scanner/sandbox tools and emit capabilities.json (Spec §27).
#
# Output: writes JSON to the path passed via --output, or to
#         mini-audit/scanner/capabilities.json if no --output.
#
# We never fail the audit on a missing tool — capabilities.json records
# availability so the runtime / agent can adapt.
set -euo pipefail

AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"
OUTPUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit-root)
      AUDIT_ROOT="$2"; shift 2;;
    --output)
      OUTPUT="$2"; shift 2;;
    -h|--help)
      cat <<'EOF'
Usage: detect-tools.sh [--audit-root PATH] [--output PATH]

Writes scanner/sandbox capability record as JSON. Default output is
mini-audit/scanner/capabilities.json.
EOF
      exit 0;;
    *)
      echo "unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "$OUTPUT" ]]; then
  OUTPUT="${AUDIT_ROOT}/scanner/capabilities.json"
fi

mkdir -p "$(dirname "$OUTPUT")"

probe_version() {
  local bin="$1"
  if command -v "$bin" >/dev/null 2>&1; then
    local ver
    ver="$("$bin" --version 2>/dev/null | head -n1 | tr -d '\r' || true)"
    printf '{"available":true,"version":%s}\n' "$(printf '%s' "$ver" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))')"
  else
    printf '{"available":false}\n'
  fi
}

python3 - <<PYEOF >"$OUTPUT"
import json, subprocess, shutil, os, sys

def probe(cmd):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    return p.returncode == 0

caps = {
    "schema_version": 1,
    "audit_root": "${AUDIT_ROOT}",
    "tools": {
        "semgrep":  probe_version("semgrep"),
        "codeql":   probe_version("codeql"),
        "gitleaks": probe_version("gitleaks"),
        "trufflehog": probe_version("trufflehog"),
        "bandit":   probe_version("bandit"),
        "shellcheck": probe_version("shellcheck"),
        "git":      probe_version("git"),
    },
    "sandbox": {
        "external_network_disabled": bool(os.environ.get("MINI_AUDIT_NO_NET")),
        "scratch_writable": os.access(os.environ.get("TMPDIR","/tmp"), os.W_OK),
        "timeout_available": probe(["which","timeout"]) or probe(["which","gtimeout"]),
        "resource_limit_available": probe(["which","prlimit"]) or probe(["which","ulimit"]),
        "environment_sanitized": bool(os.environ.get("MINI_AUDIT_SANITIZED")),
    },
}

print(json.dumps(caps, indent=2, ensure_ascii=False))
PYEOF

echo "wrote $OUTPUT" >&2