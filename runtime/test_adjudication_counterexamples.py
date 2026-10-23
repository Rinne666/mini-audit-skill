#!/usr/bin/env python3
"""Counter-example tests for validate_adjudication.py.

A validator that only ever sees valid input proves nothing. Each case
here takes the fixture — a correct adjudication — breaks it in exactly
one way, and asserts that the validator rejects the broken version.

The broken versions below are the ways this framework actually fails in
practice:

  * an absence that is asserted but does not reproduce (the ledger says
    "no matches" for a pattern that does match),
  * an unresolved conclusion resting on search evidence with no
    reproducible absence behind it,
  * a verdict asserted rather than derived,
  * a claim that does not hold carrying an acceptance verdict, so a
    non-vulnerability is dressed up as an "unacceptable" one,
  * a "confirmed" assertion backed only by a search,
  * a subject written as a consequence,
  * two copies of the same search counted as two checks,
  * work left open at delivery,
  * a divergence claimed absent without reproducible absence behind it.

Run: python runtime/test_adjudication_counterexamples.py
Exit codes: 0 all pass, 1 a test failed.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_adjudication import (  # noqa: E402
    _extract_adjudication_table,
    _load_evidence_ledger,
    validate,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "fixtures" / "mini-adjudication"
NOTES = FIXTURE / "expected" / "adjudication-notes.md"
LEDGER = FIXTURE / "expected" / "evidence.jsonl"

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"OK:   {label}")
    else:
        print(f"FAIL: {label}{(' — ' + detail) if detail else ''}")
        failures.append(label)


def extract(text: str) -> dict:
    obj, err = _extract_adjudication_table(text)
    if obj is None:
        raise SystemExit(f"fixture notes have no adjudication table: {err}")
    return obj


def rebuild(text: str, obj: dict) -> str:
    """Put a mutated table back into the notes, fences and all."""
    start = text.index("```json")
    close = text.index("```", start + len("```json"))
    body = json.dumps(obj, indent=2, ensure_ascii=False)
    return text[:start] + "```json\n" + body + "\n```" + text[close + 3:]


def claim(obj: dict, claim_id: str) -> dict:
    for entry in obj["claims"]:
        if entry["id"] == claim_id:
            return entry
    raise SystemExit(f"no claim {claim_id}")


def assertion(entry: dict, assertion_id: str) -> dict:
    for item in entry["assertions"]:
        if item["id"] == assertion_id:
            return item
    raise SystemExit(f"no assertion {assertion_id}")


def stage(tmp: Path) -> Path:
    """Copy the fixture into a temp tree so the ledger's relative cwd resolves.

    The ledger records the working directory it was captured in, relative
    to the ledger itself. Re-verifying a recorded search therefore needs
    that directory to exist with the same shape. The temp tree mirrors
    the repository layout so the recorded paths still point at the same
    files.
    """
    target = tmp / "fixtures" / "mini-adjudication"
    shutil.rmtree(target, ignore_errors=True)
    shutil.copytree(FIXTURE, target)
    return target / "expected" / "evidence.jsonl"


def run(notes_text: str, ledger_path: Path) -> list[str]:
    records, ledger_errors = _load_evidence_ledger(str(ledger_path))
    _, errors = validate(notes_text, records)
    return errors + ledger_errors


def expect_rejected(label: str, notes_text: str, ledger_path: Path, needle: str) -> None:
    errors = run(notes_text, ledger_path)
    hit = any(needle in err for err in errors)
    check(label, hit, f"expected an error containing {needle!r}, got {errors!r}")


base_text = NOTES.read_text(encoding="utf-8")

with tempfile.TemporaryDirectory() as raw_tmp:
    tmp = Path(raw_tmp)

    # 0. The fixture itself must pass, or the cases below prove nothing.
    ledger_path = stage(tmp)
    baseline_errors = run(base_text, ledger_path)
    check("the fixture itself is accepted", not baseline_errors, repr(baseline_errors))

    # 1. An absence that does not reproduce.
    #
    # This is the failure the fixture used to have: a ledger entry that
    # claimed "no matches" for a pattern that does match the source. The
    # ledger is self-reported, so nothing but a re-run catches it.
    ledger_path = stage(tmp)
    lines = ledger_path.read_text(encoding="utf-8").splitlines()
    patched = []
    for line in lines:
        record = json.loads(line)
        if record["id"] == "E000008":
            record["query"] = "getenv"
            record["command"] = [
                "rg", "--line-number", "--with-filename", "--no-heading", "--color",
                "never", "--max-count", "500", "--", "getenv",
                "fixtures/mini-adjudication/app.php",
            ]
        patched.append(json.dumps(record, sort_keys=True))
    ledger_path.write_text("\n".join(patched) + "\n", encoding="utf-8")
    expect_rejected(
        "a zero-match search that no longer reproduces is rejected",
        base_text, ledger_path, "no longer reproduces",
    )

    # 2. An unresolved conclusion resting on search evidence alone.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    entry = claim(obj, "C3")
    item = assertion(entry, "A8")
    item["evidence_ids"] = ["E000010", "E000011"]
    item.pop("absence_searches", None)
    expect_rejected(
        "an unresolved assertion on search evidence alone must show its absence",
        rebuild(base_text, obj), ledger_path, "absence_searches",
    )

    # 3. A verdict asserted rather than derived.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    claim(obj, "C3")["validity"] = "holds"
    expect_rejected(
        "a validity that does not follow from its assertions is rejected",
        rebuild(base_text, obj), ledger_path, "derive",
    )

    # 4. A claim that does not hold carrying an acceptance verdict.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    claim(obj, "C2")["acceptance"] = {
        "premise_kind": "attacker_only",
        "boundary_state": "not_declared",
        "divergence_state": "present",
        "acceptability": "accept",
        "rationale": "dressed up",
        "evidence_ids": ["E000004"],
        "divergence_sides": [
            {"file_line": "fixtures/mini-adjudication/app.php:181", "behavior": "a"},
            {"file_line": "fixtures/mini-adjudication/app.php:184", "behavior": "b"},
        ],
    }
    expect_rejected(
        "a claim that does not hold cannot carry an acceptance verdict",
        rebuild(base_text, obj), ledger_path, "must not carry an acceptance verdict",
    )

    # 5. A "confirmed" assertion backed only by a search.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    assertion(claim(obj, "C1"), "A1")["evidence_ids"] = ["E000008"]
    expect_rejected(
        "a confirmed assertion must cite a captured source read",
        rebuild(base_text, obj), ledger_path, "must cite a captured source read",
    )

    # 6. A subject written as a consequence.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    claim(obj, "C1")["subject"] = "An attacker can take over any account by name."
    expect_rejected(
        "a subject stated as a consequence is rejected",
        rebuild(base_text, obj), ledger_path, "states a consequence, not an invariant",
    )

    # 7. The same search counted twice is not two checks.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    item = assertion(claim(obj, "C3"), "A8")
    item["absence_searches"] = [{"evidence_id": "E000010"}, {"evidence_id": "E000010"}]
    expect_rejected(
        "two copies of one search are not two absence checks",
        rebuild(base_text, obj), ledger_path, "two distinct captured zero-match searches",
    )

    # 8. Work left open at delivery.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    obj["work_queue"][0]["status"] = "active"
    expect_rejected(
        "an open work item blocks delivery",
        rebuild(base_text, obj), ledger_path, "every item must be completed or deferred",
    )

    # 9. A divergence claimed absent with no reproducible absence behind it.
    ledger_path = stage(tmp)
    obj = extract(base_text)
    acceptance = claim(obj, "C1")["acceptance"]
    acceptance["divergence_state"] = "absent"
    acceptance.pop("divergence_sides", None)
    expect_rejected(
        "a divergence claimed absent must show two zero-match searches",
        rebuild(base_text, obj), ledger_path, "divergence_absence_searches",
    )

    # 10. The notes must carry the sections a reviewer scans.
    ledger_path = stage(tmp)
    stripped = re.sub(r"^#{1,4}\s*Assertion Ledger.*$", "", base_text, flags=re.MULTILINE)
    expect_rejected(
        "notes without every coverage section are rejected",
        stripped, ledger_path, "missing coverage section",
    )

if failures:
    print(f"\n{len(failures)} counter-example(s) FAILED: {failures}")
    raise SystemExit(1)
print("\nall counter-examples rejected as expected")
