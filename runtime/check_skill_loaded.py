#!/usr/bin/env python3
"""check-skill-loaded -- Runtime-side enforcement primitive (B).

Verifies that the version of SKILL.md, references and templates
the agent is currently reasoning over matches HEAD of the skill
repo. This is the second of three enforcement primitives added
after the React 19 long-chain post-mortem (2026-09-25).

The incident's second failure mode: a new session received only
"硬门禁配对表" five characters in its prompt; the substantive
predicate definitions were never loaded. The agent reverted to
natural intuition and downgraded a CRITICAL RCE on a single
unverified guard. This script prevents that.

Two modes:

  --refresh   Walk the repo, compute sha256 for every file in
              runtime/skill_manifest.json, write the manifest.

  (no flag)   Walk the repo, compute sha256 for every file, and
              compare against runtime/skill_manifest.json. Exit
              non-zero on mismatch.

Usage in a session-start hook:

    python runtime/check_skill_loaded.py
    if [ $? -ne 0 ]; then
        echo "skill stale; reloading"; exit 1
    fi

Exit codes:

    0  -- every file matches the manifest.
    1  -- at least one file is missing or hash mismatches.
    2  -- manifest itself is missing or malformed.

This script is intentionally stdlib-only and makes no network
calls. It compares against a checked-in manifest, not a remote
source of truth, so the comparison is hermetic.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

MANIFEST_PATH = Path(__file__).resolve().parent / "skill_manifest.json"
REPO_ROOT = MANIFEST_PATH.resolve().parent.parent


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest() -> dict:
    if not MANIFEST_PATH.exists():
        print(f"FAIL: manifest missing at {MANIFEST_PATH}", file=sys.stderr)
        sys.exit(2)
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"FAIL: manifest malformed: {exc}", file=sys.stderr)
        sys.exit(2)
    if "files" not in manifest or not isinstance(manifest["files"], dict):
        print("FAIL: manifest has no 'files' dict", file=sys.stderr)
        sys.exit(2)
    return manifest


def refresh() -> int:
    manifest = _load_manifest()
    new_files: dict[str, str] = {}
    for relpath in manifest["files"]:
        path = REPO_ROOT / relpath
        if not path.exists():
            print(f"FAIL: file missing during refresh: {relpath}", file=sys.stderr)
            return 1
        new_files[relpath] = _sha256(path)
    manifest["files"] = new_files
    import time
    manifest["generated_at_unix"] = int(time.time())
    MANIFEST_PATH.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"OK: refreshed {len(new_files)} files in {MANIFEST_PATH}")
    return 0


def check() -> int:
    manifest = _load_manifest()
    failures: list[str] = []
    for relpath, expected in manifest["files"].items():
        if expected.startswith("PLACEHOLDER"):
            failures.append(f"{relpath}: manifest has placeholder hash; run --refresh")
            continue
        path = REPO_ROOT / relpath
        if not path.exists():
            failures.append(f"{relpath}: file missing")
            continue
        actual = _sha256(path)
        if actual != expected:
            failures.append(f"{relpath}: hash mismatch (manifest={expected[:12]}... actual={actual[:12]}...)")
    if failures:
        for f in failures:
            print(f"FAIL: {f}", file=sys.stderr)
        print(f"FAIL: {len(failures)} file(s) stale; re-run --refresh and reload", file=sys.stderr)
        return 1
    print(f"OK: {len(manifest['files'])} file(s) match manifest")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check that the in-context skill matches the checked-in manifest.")
    parser.add_argument("--refresh", action="store_true", help="Recompute hashes for every tracked file and update the manifest.")
    args = parser.parse_args(argv)
    if args.refresh:
        return refresh()
    return check()


if __name__ == "__main__":
    raise SystemExit(main())