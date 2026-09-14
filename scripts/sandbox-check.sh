#!/usr/bin/env bash
# Sandbox availability probe (Spec §25). Returns non-zero if the runtime
# is missing critical isolation capabilities required to execute
# target-controlled code (PoC executors).
#
# Usage:
#   sandbox-check.sh [--strict]
#
# Always writes JSON to mini-audit/sandbox/probe.json (or AUDIT_ROOT/sandbox/probe.json).
# Exit code: 0 if all critical capabilities present, 1 otherwise.
# With --strict, also fails on warnings.
set -euo pipefail

STRICT=0
AUDIT_ROOT="${AUDIT_ROOT:-mini-audit}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --strict) STRICT=1; shift;;
    --audit-root) AUDIT_ROOT="$2"; shift 2;;
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

python3 - <<PYEOF >"$OUTPUT"
import json, os, shutil, subprocess, sys

def probe(cmd):
    return shutil.which(cmd) is not None or subprocess.run(cmd, capture_output=True, timeout=5).returncode == 0

def has_env(name):
    return bool(os.environ.get(name))

caps = {
    "schema_version": 1,
    "strict": bool(${STRICT}),
    "checks": {
        "sandbox_available": has_env("MINI_AUDIT_SANDBOX") or probe(["which","bwrap"]) or probe(["which","docker"]),
        "external_network_disabled": has_env("MINI_AUDIT_NO_NET"),
        "safe_writable_scratch": os.access(os.environ.get("SCRATCH", os.environ.get("TMPDIR","/tmp")), os.W_OK),
        "timeout_available": probe(["which","timeout"]) or probe(["which","gtimeout"]),
        "resource_limit_available": probe(["which","prlimit"]),
        "environment_sanitized": has_env("MINI_AUDIT_SANITIZED"),
    },
}

critical = ["sandbox_available", "safe_writable_scratch", "timeout_available"]
all_critical_pass = all(caps["checks"][k] for k in critical)
any_warning = not all(caps["checks"].values())

caps["verdict"] = "ok" if all_critical_pass else "blocked"
caps["warnings"] = [k for k,v in caps["checks"].items() if not v]

print(json.dumps(caps, indent=2, ensure_ascii=False))
PYEOF

# Decide exit code
python3 - <<PYEOF
import json
with open("$OUTPUT", encoding="utf-8") as f:
    caps = json.load(f)
if caps["verdict"] != "ok":
    sys.exit(1)
if ${STRICT} and caps["warnings"]:
    sys.exit(1)
PYEOF

echo "wrote $OUTPUT (verdict=$(python3 -c 'import json;print(json.load(open("'"$OUTPUT"'"))["verdict"])'))" >&2