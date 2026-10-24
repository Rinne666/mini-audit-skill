#!/usr/bin/env python3
"""regression -- Runtime-side enforcement primitive (C).

Fixture-driven self-test for the adjudication framework. Locks the
output format an adjudication must produce so that prompt-side
regressions break loudly.

The script does NOT call an LLM. It validates that the canonical
"correct adjudication output" for each fixture passes the enforcement
primitives in this repo:

  - test-validate-adjudication (the mechanical derivation rules that
    turn assertions and acceptance answers into verdicts)
  - test-adjudication-counterexamples (fourteen ways a correct
    adjudication can be broken, each of which must be rejected)
  - validate-adjudication (atomic propositions, evidence citations,
    two-layer verdict consistency, work queue closure, channel)
  - check-skill-loaded (file-fingerprint manifest)
  - cvss31 --selftest (the CVSS cross-check anchors)

What this proves: the format an adjudication must produce is
structurally enforced.

What this does NOT prove: that an LLM, given the skill and a real
target, will produce that format, or that the maintainer will accept
the resulting report.

Usage:

    python runtime/regression.py
    python runtime/regression.py --fixture fixtures/mini-adjudication

Exit codes:
    0  every fixture's expected output passes every check.
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
RUNTIME = REPO_ROOT / "runtime"

# Use the interpreter that is running this script, so the check works on
# Windows where `python3` is not on PATH.
PY = sys.executable or "python3"


def _run(cmd: list[str]) -> tuple[int, str]:
    """Run a subprocess and return (exit_code, combined_output)."""
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    out = (result.stdout or "").strip() + (result.stderr or "").strip()
    return result.returncode, out


def check_fixture(fixture_dir: Path) -> tuple[bool, list[str]]:
    """Validate one fixture's expected/adjudication-notes.md against the primitives."""
    notes = fixture_dir / "expected" / "adjudication-notes.md"
    evidence = fixture_dir / "expected" / "evidence.jsonl"
    if not notes.exists():
        return False, [f"missing expected/adjudication-notes.md in {fixture_dir}"]
    if not evidence.exists():
        return False, [f"missing expected/evidence.jsonl in {fixture_dir}"]
    failures: list[str] = []

    # 1. validate-adjudication
    code, out = _run([
        PY,
        str(RUNTIME / "validate_adjudication.py"),
        str(notes),
        "--evidence-ledger",
        str(evidence),
    ])
    if code != 0:
        failures.append(f"validate-adjudication exit {code}: {out}")

    # 2. check-skill-loaded
    code, out = _run([PY, str(RUNTIME / "check_skill_loaded.py")])
    if code != 0:
        failures.append(f"check-skill-loaded exit {code}: {out}")

    return (len(failures) == 0), failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run regression on every fixture in fixtures/.")
    parser.add_argument("--fixture", type=Path, help="Run only this fixture (relative to repo root or absolute).")
    args = parser.parse_args(argv)

    # The derivation rules are part of the framework's guarantees: the
    # verdicts are derived, not asserted by the model.
    code, out = _run([PY, str(RUNTIME / "test_validate_adjudication.py")])
    if code != 0:
        print(f"FAIL: test-validate-adjudication exit {code}: {out}", file=sys.stderr)
        return 1
    print("-- test_validate_adjudication")
    print("   OK")

    code, out = _run([PY, str(RUNTIME / "test_adjudication_counterexamples.py")])
    if code != 0:
        print(f"FAIL: test-adjudication-counterexamples exit {code}: {out}", file=sys.stderr)
        return 1
    print("-- test_adjudication_counterexamples")
    print("   OK")

    # The CVSS cross-check is part of the framework's guarantees.
    code, out = _run([PY, str(RUNTIME / "cvss31.py"), "--selftest"])
    if code != 0:
        print(f"FAIL: cvss31 selftest exit {code}: {out}", file=sys.stderr)
        return 1
    print("-- cvss31 selftest")
    print("   OK")

    if args.fixture:
        fixtures = [args.fixture.resolve()]
    else:
        fixtures = sorted(p for p in FIXTURES_ROOT.iterdir() if p.is_dir()) if FIXTURES_ROOT.exists() else []

    if not fixtures:
        print("FAIL: no fixtures found", file=sys.stderr)
        return 2

    overall_ok = True
    for fixture in fixtures:
        try:
            label = fixture.relative_to(REPO_ROOT)
        except ValueError:
            label = fixture
        print(f"-- {label}")
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
    print("\nFAIL: at least one fixture failed regression", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
