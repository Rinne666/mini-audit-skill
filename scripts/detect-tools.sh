#!/usr/bin/env bash
# Detect available scanner/sandbox tools and emit capabilities.json (Spec §27).
#
# Output: writes JSON to the path passed via --output, or to
#         mini-audit/scanner/capabilities.json if no --output.
#
# We never fail the audit on a missing tool — capabilities.json records
# availability so the runtime / agent can adapt.
#
# Hardening v1.1 §7: all probing happens in ONE language. v1.0 defined a bash
# `probe_version()` helper and then called it from inside a Python heredoc,
# where it did not exist — every tool was reported unavailable. Detection now
# runs entirely in Python; this script is only argument parsing + dispatch.
set -euo pipefail

AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"
OUTPUT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --audit-root)
      AUDIT_ROOT="${2:-}"; shift 2;;
    --output)
      OUTPUT="${2:-}"; shift 2;;
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

PYTHON_BIN="${PYTHON_BIN:-python3}"
if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "python3 is required by detect-tools.sh" >&2
  exit 3
fi

AUDIT_ROOT="$AUDIT_ROOT" OUTPUT="$OUTPUT" "$PYTHON_BIN" - <<'PYEOF'
"""Probe scanner/sandbox tool availability and write capabilities.json."""
import json
import os
import shutil
import subprocess
from pathlib import Path

AUDIT_ROOT = os.environ["AUDIT_ROOT"]
OUTPUT = Path(os.environ["OUTPUT"])

TOOLS = {
    "semgrep": "semgrep",
    "codeql": "codeql",
    "gitleaks": "gitleaks",
    "trufflehog": "trufflehog",
    "bandit": "bandit",
    "shellcheck": "shellcheck",
    "git": "git",
}


def probe_version(bin_name):
    """Return {'available': bool, 'path': str, 'version': str}."""
    path = shutil.which(bin_name)
    if path is None:
        return {"available": False}
    version = ""
    for flag in ("--version", "version", "-V"):
        try:
            proc = subprocess.run(
                [path, flag],
                capture_output=True, text=True, timeout=10, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        text = (proc.stdout or proc.stderr or "").strip()
        if text:
            version = text.splitlines()[0].strip()
            break
    return {"available": True, "path": path, "version": version}


def has_binary(*names):
    return any(shutil.which(n) is not None for n in names)


caps = {
    "schema_version": 1,
    "audit_root": AUDIT_ROOT,
    "tools": {name: probe_version(bin_name) for name, bin_name in TOOLS.items()},
    "sandbox": {
        "external_network_disabled": bool(os.environ.get("MINI_AUDIT_NO_NET")),
        "scratch_writable": os.access(
            os.environ.get("SCRATCH", os.environ.get("TMPDIR", "/tmp")), os.W_OK
        ),
        "timeout_available": has_binary("timeout", "gtimeout"),
        "resource_limit_available": has_binary("prlimit") or has_binary("ulimit"),
        "environment_sanitized": bool(os.environ.get("MINI_AUDIT_SANITIZED")),
        "sandbox_available": bool(os.environ.get("MINI_AUDIT_SANDBOX"))
        or has_binary("bwrap", "docker"),
    },
}

OUTPUT.write_text(json.dumps(caps, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
PYEOF

echo "wrote $OUTPUT" >&2
