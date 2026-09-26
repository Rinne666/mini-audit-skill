#!/usr/bin/env python3
"""regression -- Runtime-side enforcement primitive (C).

Fixture-driven self-test for the audit framework. Locks the
output format the audit must produce so that prompt-side
regressions break loudly.

This is the third of three enforcement primitives added
after the React 19 long-chain post-mortem (2026-09-25).

The script does NOT call an LLM. It validates that the
canonical "correct audit output" for each fixture passes
the two enforcement primitives already in this repo:

  - validate-notes (pairing-table schema + Coverage paragraph)
  - check-skill-loaded (file-fingerprint manifest)

What this proves: the format the audit must produce is
structurally enforced.

What this does NOT prove: that an LLM, given the skill and
a real target, will produce that format. The LLM-in-the-loop
trial is out-of-band. This script only catches the failure
mode where the framework regresses in format.

Usage:

    python runtime/regression.py
    python runtime/regression.py --fixture fixtures/mini-poi

Exit codes:

    0  every fixture's expected output passes both checks.
    1  at least one fixture fails.
    2  no fixtures found.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_ROOT = REPO_ROOT / "fixtures"


def _run(cmd: list[str]) -> tuple[int, str]:
    """Run a subprocess and return (exit_code, stdout_stripped)."""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    out = (result.stdout or "").strip() + (result.stderr or "").strip()
    return result.returncode, out


def check_fixture(fixture_dir: Path) -> tuple[bool, list[str]]:
    """Validate one fixture's expected/notes.md against the two primitives."""
    notes = fixture_dir / "expected" / "notes.md"
    if not notes.exists():
        return False, [f"missing expected/notes.md in {fixture_dir}"]
    failures: list[str] = []

    # 1. validate-notes
    code, out = _run(["python3", str(REPO_ROOT / "runtime" / "validate_notes.py"), str(notes)])
    if code != 0:
        failures.append(f"validate-notes exit {code}: {out}")

    # 2. check-skill-loaded
    code, out = _run(["python3", str(REPO_ROOT / "runtime" / "check_skill_loaded.py")])
    if code != 0:
        failures.append(f"check-skill-loaded exit {code}: {out}")

    return (len(failures) == 0), failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run regression on every fixture in fixtures/.")
    parser.add_argument("--fixture", type=Path, help="Run only this fixture (relative to repo root or absolute).")
    args = parser.parse_args(argv)

    if args.fixture:
        fixtures = [args.fixture.resolve()]
    else:
        fixtures = sorted(p for p in FIXTURES_ROOT.iterdir() if p.is_dir()) if FIXTURES_ROOT.exists() else []

    if not fixtures:
        print("FAIL: no fixtures found", file=sys.stderr)
        return 2

    overall_ok = True
    for fixture in fixtures:
        print(f"-- {fixture.relative_to(REPO_ROOT)}")
        ok, failures = check_fixture(fixture)
        if ok:
            print("   OK")
        else:
            overall_ok = False
            for f in failures:
                print(f"   FAIL: {f}", file=sys.stderr)

    if overall_ok:
        print(f"\nOK: {len(fixtures)} fixture(s) pass regression")
        return 0
    print(f"\nFAIL: at least one fixture failed regression", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())