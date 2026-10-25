#!/usr/bin/env python3
"""Phase-gate and Stop-gate tests for validate_adjudication.py / stop_gate.py.

Two enforcement layers, two test groups:

  Phase gates (`--phase` / `--next`): the validator must require exactly
  what each stage owes — a mid-work run returns the next owed
  requirement, not a wall of end-state failures. Stripping the
  acceptance answers must fail assess, not adjudicate; stripping a
  submission block must fail deliver, not assess.

  Stop gate (`validate_partial` + `runtime/stop_gate.py`): a turn may
  end on an honest mid-work state (half-written assertion rows, no
  acceptance yet), may never end on a contradictory one (a verdict that
  does not derive, cited evidence that does not exist), and once
  delivery is claimed the full deliver gate must pass. The gate must
  fail open after MAX_BLOCKS consecutive blocks.

Run: python runtime/test_phase_and_gate.py
Exit codes: 0 all pass, 1 a test failed.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_adjudication import (  # noqa: E402
    _extract_adjudication_table,
    _load_evidence_ledger,
    validate,
    validate_partial,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURE = REPO_ROOT / "fixtures" / "mini-adjudication"
NOTES = FIXTURE / "expected" / "adjudication-notes.md"
LEDGER = FIXTURE / "expected" / "evidence.jsonl"
STOP_GATE = REPO_ROOT / "runtime" / "stop_gate.py"

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"OK:   {label}")
    else:
        print(f"FAIL: {label}{(' — ' + detail) if detail else ''}")
        failures.append(label)


def load() -> tuple[str, dict, dict[str, dict]]:
    text = NOTES.read_text(encoding="utf-8")
    obj, err = _extract_adjudication_table(text)
    if obj is None:
        raise SystemExit(f"fixture notes have no adjudication table: {err}")
    records, ledger_errors = _load_evidence_ledger(str(LEDGER))
    if ledger_errors:
        raise SystemExit(f"fixture ledger failed to load: {ledger_errors}")
    return text, obj, records


def rebuild(text: str, obj: dict) -> str:
    start = text.index("```json")
    close = text.index("```", start + len("```json"))
    body = json.dumps(obj, indent=2, ensure_ascii=False)
    return text[:start] + "```json\n" + body + "\n```" + text[close + 3:]


def claim(obj: dict, claim_id: str) -> dict:
    return next(c for c in obj["claims"] if c["id"] == claim_id)


# --- phase gates -----------------------------------------------------------

text, obj, records = load()

for phase in ("adjudicate", "assess", "deliver"):
    code, errors = validate(text, records, phase=phase)
    check(f"valid fixture passes {phase} gate", code == 0, "; ".join(errors[:2]))

# No acceptance answers: adjudicate stays green, assess and deliver go red.
_, no_acceptance, _ = load()
del claim(no_acceptance, "C1")["acceptance"]
no_acceptance_text = rebuild(text, no_acceptance)
code, _ = validate(no_acceptance_text, records, phase="adjudicate")
check("stripped acceptance does not fail adjudicate", code == 0)
code, errors = validate(no_acceptance_text, records, phase="assess")
check("stripped acceptance fails assess", code == 1, "; ".join(errors[:2]))
code, _ = validate(no_acceptance_text, records, phase="deliver")
check("stripped acceptance fails deliver", code == 1)

# No submission block (acceptance intact): assess stays green, deliver red.
_, no_submission, _ = load()
del claim(no_submission, "C1")["submission"]
no_submission_text = rebuild(text, no_submission)
code, _ = validate(no_submission_text, records, phase="assess")
check("stripped submission does not fail assess", code == 0)
code, errors = validate(no_submission_text, records, phase="deliver")
check("stripped submission fails deliver", code == 1, "; ".join(errors[:2]))

# --next walks the phases and prints exactly one instruction.
result = subprocess.run(
    [sys.executable, str(REPO_ROOT / "runtime" / "validate_adjudication.py"), str(NOTES),
     "--evidence-ledger", str(LEDGER), "--next"],
    capture_output=True, text=True, check=False,
)
check("--next prints READY on the valid fixture",
      result.returncode == 0 and result.stdout.startswith("READY"), result.stdout.strip())

with tempfile.TemporaryDirectory() as tmpdir:
    broken_notes = Path(tmpdir) / "adjudication-test.md"
    broken_notes.write_text(no_submission_text, encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "runtime" / "validate_adjudication.py"), str(broken_notes),
         "--evidence-ledger", str(LEDGER), "--next"],
        capture_output=True, text=True, check=False,
    )
    check("--next prints the first owed deliver requirement",
          result.returncode == 0 and result.stdout.startswith("NEXT [deliver]:"),
          result.stdout.strip().splitlines()[:1])

# --- validate_partial: mid-work states pass, contradictions block ----------

check("partial: fresh template copy (no JSON) passes",
      validate_partial("# notes\nno table here\n", {})[0] == 0)

check("partial: unparseable JSON fence blocks",
      validate_partial("```json\n{\n```\n", {})[0] == 1)

check("partial: empty claims list passes (intake not done)",
      validate_partial(rebuild(text, {**obj, "claims": []}), records)[0] == 0)

# A half-written assertion row and an unset validity: honest mid-work.
_, mid_work, _ = load()
c1 = claim(mid_work, "C1")
c1["assertions"][0] = {"id": "A1", "type": "defect", "statement": "..."}
c1["validity"] = None
c1["action"] = None
for field in ("acceptance", "subject", "submission"):
    c1.pop(field, None)
check("partial: half-written assertion rows pass",
      validate_partial(rebuild(text, mid_work), records)[0] == 0)

# A completed claim whose validity does not derive: contradiction, blocks.
_, bad_verdict, _ = load()
claim(bad_verdict, "C2")["validity"] = "holds"
code, errors = validate_partial(rebuild(text, bad_verdict), records)
check("partial: non-derived validity blocks", code == 1, "; ".join(errors[:2]))

# A holding claim with no acceptance yet, actioned hardening_note (not
# delivery): mid-assess state, passes.
_, assessing, _ = load()
c1 = claim(assessing, "C1")
c1["action"] = "hardening_note"
for field in ("acceptance", "subject", "submission"):
    c1.pop(field, None)
check("partial: holding claim without acceptance (not delivery) passes",
      validate_partial(rebuild(text, assessing), records)[0] == 0)

# The same state but actioned report: delivery claimed, full gate applies.
_, reportable, _ = load()
c1 = claim(reportable, "C1")
c1["action"] = "report"
for field in ("acceptance", "subject", "submission"):
    c1.pop(field, None)
code, errors = validate_partial(rebuild(text, reportable), records)
check("partial: report action without submission blocks", code == 1, "; ".join(errors[:2]))

# --- stop_gate end-to-end (subprocess, simulated hook payload) -------------


def run_gate(project: Path, session: str) -> tuple[int, str]:
    env = dict(os.environ)
    env["ZCODE_PROJECT_DIR"] = str(project)
    result = subprocess.run(
        [sys.executable, str(STOP_GATE)],
        input=json.dumps({"session_id": session, "cwd": str(project)}),
        capture_output=True, text=True, env=env, check=False,
    )
    return result.returncode, result.stdout.strip()


def make_project() -> tuple[Path, Path, Path]:
    tmpdir = tempfile.mkdtemp(prefix="stopgate_")
    project = Path(tmpdir) / "proj"
    workspace = project / "adjudication"
    workspace.mkdir(parents=True)
    for item in FIXTURE.joinpath("expected").iterdir():
        if item.is_file():
            shutil.copy2(item, workspace / item.name)
        elif item.is_dir():
            shutil.copytree(item, workspace / item.name)
    return project, workspace, workspace / "adjudication-notes.md"


# No notes file in the project: the gate is silent.
with tempfile.TemporaryDirectory() as tmpdir:
    empty = Path(tmpdir) / "proj"
    empty.mkdir()
    code, out = run_gate(empty, "t-empty")
    check("stop_gate: no adjudication active -> silent pass", code == 0 and out == "", out)

# Valid fixture (its C1 is actioned report, so the full deliver gate
# applies): passes.
project, workspace, notes_path = make_project()
code, out = run_gate(project, "t-valid")
check("stop_gate: valid delivered state passes", code == 0 and out == "", out)

# Fresh template copy: intake not done, silent pass.
shutil.copy2(REPO_ROOT / "templates" / "adjudication-notes.md", notes_path)
code, out = run_gate(project, "t-fresh")
check("stop_gate: fresh template copy passes", code == 0 and out == "", out)

# Broken JSON fence: corruption blocks.
notes_path.write_text(
    notes_path.read_text(encoding="utf-8") + "\n```json\n{\n```\n", encoding="utf-8"
)
code, out = run_gate(project, "t-corrupt")
blocked = code == 0 and out.startswith("{") and json.loads(out).get("decision") == "block"
check("stop_gate: corrupted table blocks", blocked, out[:120])

# Delivery claimed by an artifact on an invalid state: blocks, with a
# repair instruction naming --next.
shutil.copy2(FIXTURE / "expected" / "adjudication-notes.md", notes_path)
obj_mut, err = _extract_adjudication_table(notes_path.read_text(encoding="utf-8"))
del claim(obj_mut, "C1")["submission"]
notes_path.write_text(rebuild(notes_path.read_text(encoding="utf-8"), obj_mut), encoding="utf-8")
(workspace / "advisory.md").write_text("# Advisory draft\n", encoding="utf-8")
code, out = run_gate(project, "t-deliver")
payload = json.loads(out) if out.startswith("{") else {}
check("stop_gate: delivery artifact over invalid state blocks",
      payload.get("decision") == "block", out[:120])
check("stop_gate: block reason points at the --next driver",
      "--next" in payload.get("reason", ""), payload.get("reason", "")[:200])

# Evidence cited but the ledger is gone: contradiction, blocks.
(workspace / "advisory.md").unlink()
(workspace / "evidence.jsonl").unlink()
code, out = run_gate(project, "t-noledger")
payload = json.loads(out) if out.startswith("{") else {}
check("stop_gate: cited evidence with no ledger blocks",
      payload.get("decision") == "block", out[:120])

# Fail-open: after MAX_BLOCKS consecutive blocks the gate passes.
code, out = run_gate(project, "t-failopen")
check("stop_gate: still blocks before the limit",
      json.loads(out).get("decision") == "block" if out.startswith("{") else False)
for _ in range(2):
    run_gate(project, "t-failopen")
code, out = run_gate(project, "t-failopen")
check("stop_gate: fails open after repeated blocks", code == 0 and out == "", out)

shutil.rmtree(project.parent, ignore_errors=True)

if failures:
    print(f"\n{len(failures)} test(s) FAILED: {failures}")
    raise SystemExit(1)
print("\nall phase-gate and stop-gate tests passed")
