#!/usr/bin/env python3
"""stop_gate -- the Stop-event hard gate for the mini-adjudication skill.

Installed as a ZCode `Stop` hook, this is the enforcement layer the
skill's prose always assumed but never had: the model may not end a
turn on an adjudication state that is inconsistent with what it claims.

What it does, in order:

  1. Find the adjudication notes file (`adjudication*.md`) in the
     project. No notes file means no adjudication is active in this
     session's project — exit 0 silently, immediately.
  2. Check skill freshness (check_skill_loaded). A stale skill means
     the model is reasoning over instructions that no longer match this
     framework — block once, loudly.
  3. Run validate_partial: everything recorded must be valid (derived
     verdicts, cited evidence that exists, acceptance/submission blocks
     that exist must be complete and consistent). Completeness below
     delivery is NOT enforced — an adjudication may honestly be mid-work
     when a turn ends.
  4. If delivery is claimed — an advisory / submission-summary /
     refutation artifact sits next to the notes, or any claim is
     actioned `report` / `rewrite_then_report` — the FULL deliver gate
     must pass. This is the "no delivering on a red gate" rule.

Fail-open design: after MAX_BLOCKS consecutive blocks in one session,
the gate passes with a stderr warning. A gate that wedges a session is
worse than a gate that occasionally lets one through.

Hook I/O: reads the hook payload (session_id, cwd) from stdin; on a
block prints `{"decision": "block", "reason": "..."}` and exits 0; on a
pass prints nothing and exits 0. Never blocks a project that has no
adjudication in flight.

Exit codes:
    0  always (the decision travels in the JSON, not the exit code)
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

RUNTIME_DIR = Path(__file__).resolve().parent
SKILL_ROOT = RUNTIME_DIR.parent
sys.path.insert(0, str(RUNTIME_DIR))

import check_skill_loaded  # noqa: E402
import validate_adjudication as va  # noqa: E402

MAX_BLOCKS = 3
MAX_VISITED_DIRS = 5000
MAX_DEPTH = 5
# Directories that never contain an adjudication workspace, and that
# make walks slow when not pruned. The skill's own templates/ and
# fixtures/ live under SKILL_ROOT, which is excluded wholesale below.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    "dist", "build", ".zcode", ".agents", ".idea", ".vscode", "vendor",
    "target", "templates", "fixtures",
}
NOTES_NAME_PREFIX = "adjudication"
ARTIFACT_PREFIXES = ("advisory", "submission-summary", "refutation")
LEDGER_NAME = "evidence.jsonl"
REASON_MAX_CHARS = 1500


def _find_notes(project: Path) -> Path | None:
    """Locate the most recently modified adjudication notes file."""
    latest: tuple[float, Path] | None = None
    visited = 0
    project = project.resolve()
    for dirpath, dirnames, filenames in os.walk(project):
        depth = Path(dirpath).relative_to(project).parts
        if len(depth) >= MAX_DEPTH:
            dirnames[:] = []
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        visited += 1
        if visited > MAX_VISITED_DIRS:
            break
        for filename in filenames:
            if not filename.lower().startswith(NOTES_NAME_PREFIX):
                continue
            if not filename.lower().endswith(".md"):
                continue
            candidate = (Path(dirpath) / filename).resolve()
            try:
                candidate.relative_to(SKILL_ROOT)
                continue  # the skill's own templates/fixtures
            except ValueError:
                pass
            mtime = candidate.stat().st_mtime
            if latest is None or mtime > latest[0]:
                latest = (mtime, candidate)
    return latest[1] if latest else None


def _find_ledger(notes: Path) -> Path | None:
    """The evidence ledger sits beside the notes (evidence.jsonl)."""
    beside = notes.parent / LEDGER_NAME
    if beside.exists():
        return beside
    jsonl_files = sorted(notes.parent.glob("*.jsonl"))
    return jsonl_files[0] if jsonl_files else None


def _delivery_artifacts_present(notes: Path) -> bool:
    for entry in sorted(notes.parent.iterdir()):
        name = entry.name.lower()
        if not entry.is_file():
            continue
        if name.endswith(".md") and name.startswith(ARTIFACT_PREFIXES):
            return True
    return False


def _counter_path(session_id: str, notes: Path) -> Path:
    key = hashlib.sha256((session_id + "|" + str(notes.resolve())).encode("utf-8")).hexdigest()[:16]
    return Path(tempfile.gettempdir()) / f"mini_adj_gate_{key}.cnt"


def _bump(counter: Path) -> int:
    count = 0
    if counter.exists():
        try:
            count = int(counter.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            count = 0
    count += 1
    try:
        counter.write_text(str(count), encoding="utf-8")
    except OSError:
        pass
    return count


def _block(reason: str) -> int:
    print(json.dumps({"decision": "block", "reason": reason[:REASON_MAX_CHARS]}))
    return 0


def main() -> int:
    payload: dict = {}
    try:
        raw = sys.stdin.read()
        if raw.strip():
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                payload = loaded
    except (json.JSONDecodeError, OSError):
        payload = {}

    project = None
    for source in (
        os.environ.get("ZCODE_PROJECT_DIR"),
        os.environ.get("CLAUDE_PROJECT_DIR"),
        payload.get("cwd") if isinstance(payload.get("cwd"), str) else None,
    ):
        if source and Path(source).is_dir():
            project = Path(source)
            break
    if project is None:
        project = Path.cwd()

    notes = _find_notes(project)
    if notes is None:
        return 0  # no adjudication active in this project

    session_id = str(payload.get("session_id") or "nosession")
    counter = _counter_path(session_id, notes)

    def pass_gate() -> int:
        try:
            counter.unlink(missing_ok=True)
        except OSError:
            pass
        return 0

    # Freshness: a stale skill means the instructions in context do not
    # match this framework. Say so once, loudly, then fail open. The
    # check's stdout is swallowed — hook stdout must be the decision JSON
    # and nothing else.
    freshness_errors: list[str] = []
    try:
        import contextlib
        import io

        with contextlib.redirect_stdout(io.StringIO()):
            if check_skill_loaded.check() != 0:
                freshness_errors.append(
                    "mini-adjudication skill files do not match runtime/skill_manifest.json — the skill "
                    "instructions in context are stale. Re-sync the skill (and re-run "
                    "check_skill_loaded.py --refresh after editing it), then reload SKILL.md."
                )
    except Exception as exc:  # noqa: BLE001 - a broken check must not wedge the gate
        freshness_errors.append(f"check_skill_loaded raised {exc!r}")

    ledger = _find_ledger(notes)
    records: dict[str, dict] = {}
    ledger_errors: list[str] = []
    if ledger is not None:
        records, ledger_errors = va._load_evidence_ledger(str(ledger))

    text = notes.read_text(encoding="utf-8", errors="replace")
    deliver_claimed = _delivery_artifacts_present(notes)
    code, errors = va.validate_partial(text, records, deliver_claimed=deliver_claimed)
    if ledger is not None and ledger_errors:
        code = 1
        errors = errors + [e for e in ledger_errors if e not in errors]

    if code == 0 and not freshness_errors:
        return pass_gate()

    attempts = _bump(counter)
    if attempts > MAX_BLOCKS:
        print(
            f"stop_gate: failing open after {attempts - 1} consecutive blocks on {notes.name}; "
            f"the adjudication state below is still not valid — review it manually.",
            file=sys.stderr,
        )
        return 0

    shown = errors[:8] + freshness_errors[:1]
    reason_lines = [
        f"mini-adjudication Stop gate: the adjudication state in {notes.name} is not "
        f"{'consistent' if not deliver_claimed else 'ready to deliver'} ({len(errors)} issue(s))."
    ]
    for err in shown:
        reason_lines.append(f"- {err}")
    reason_lines.append(
        "Fix the notes file, then re-run the driver and follow its NEXT instruction until READY:\n"
        f"  python \"{RUNTIME_DIR / 'validate_adjudication.py'}\" \"{notes}\""
        + (f" --evidence-ledger \"{ledger}\"" if ledger is not None else "")
        + " --next"
    )
    return _block("\n".join(reason_lines))


if __name__ == "__main__":
    raise SystemExit(main())
