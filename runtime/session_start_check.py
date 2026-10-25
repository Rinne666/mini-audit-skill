#!/usr/bin/env python3
"""session_start_check -- SessionStart hook for the mini-adjudication skill.

Runs check_skill_loaded at session start and, when the skill files do
not match the manifest, injects a warning into the conversation as
`additionalContext`. It never blocks and never errors: a freshness
warning must not be able to wedge a session.

Output: nothing on stdout (and exit 0) when fresh; a single JSON object
{"additionalContext": "..."} (and exit 0) when stale.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parent
MAX_CONTEXT_CHARS = 1200


def main() -> int:
    result = subprocess.run(
        [sys.executable or "python", str(RUNTIME_DIR / "check_skill_loaded.py")],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if result.returncode == 0:
        return 0

    detail = (result.stderr or result.stdout or "").strip().splitlines()
    shown = "\n".join(detail[:6])[:MAX_CONTEXT_CHARS]
    context = (
        "⚠️ mini-adjudication skill freshness check FAILED — the SKILL.md / references / "
        "templates currently available to you may not match runtime/skill_manifest.json. "
        "Before running any adjudication: re-sync the skill copy (or, if you just edited "
        "the skill, run `python runtime/check_skill_loaded.py --refresh`), then reload "
        "SKILL.md. Details:\n" + shown
    )
    print(json.dumps({"additionalContext": context}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
