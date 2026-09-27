#!/usr/bin/env python3
"""validate-notes -- structural checks for audit notes.

Validates the pairing table, baseline class-coverage ledger, guard
evaluation ledger, and Coverage section shape described in
schemas/pairing-table.schema.json and SKILL.md.

This is one of three enforcement primitives added after the
React 19 long-chain false-negative incident (post-mortem
2026-09-25). The model is expected to produce the table; this
CLI checks it against the evidence logger's records. If validation
fails, Report cannot start.

Usage:

    python runtime/validate_notes.py path/to/notes.md --evidence-ledger path/to/evidence.jsonl
    python runtime/validate_notes.py - --evidence-ledger audit/evidence.jsonl

Exit codes:

    0  -- required ledger structure and section markers are present
    1  -- pairing table or evidence ledger missing or unparsable
    2  -- pairing table malformed (schema violation)
    3  -- required section marker missing

The validator does NOT establish that searches were performed,
that the inventories are complete, or that the conclusions are
correct. It only rejects missing or underspecified records. A
reviewer must still challenge category selection, N/A and DISPROVED
decisions, and guard verdicts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "pairing-table.schema.json"

# Recognised markers for the Coverage paragraph. The notes file
# is Markdown; the Coverage paragraph may be titled or
# labelled in any of these forms.
COVERAGE_MARKERS = (
    re.compile(r"^##\s+Coverage\s+paragraph\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^##\s+Coverage\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^###\s+Coverage\b", re.MULTILINE | re.IGNORECASE),
)
CLASS_COVERAGE_MARKERS = (
    re.compile(r"^##\s+Class Coverage\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^###\s+Class Coverage\b", re.MULTILINE | re.IGNORECASE),
)
GUARD_LEDGER_MARKERS = (
    re.compile(r"^##\s+Guard Evaluation Ledger\b", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^###\s+Guard Evaluation Ledger\b", re.MULTILINE | re.IGNORECASE),
)
REQUIRED_CATEGORIES = {
    "authz_sensitive_write",
    "identity_to_decision",
    "callback_to_sink",
    "state_cross_endpoint",
}
FILE_LINE = re.compile(r"\S+:[0-9]+(?:-[0-9]+)?")


def _extract_pairing_table(markdown_text: str) -> tuple[dict | None, str | None]:
    """Pull the pairing-table JSON object out of the notes file.

    Accepts two forms:

    1. A fenced JSON block whose first object matches the schema
       (the conventional form).
    2. A bare JSON object (less common but valid).

    Returns (parsed_object, error_message). error_message is
    None on success.
    """
    # Try fenced JSON first.
    fences = re.findall(
        r"```(?:json)?\s*(\{.*?\})\s*```",
        markdown_text,
        re.DOTALL,
    )
    for candidate in fences:
        try:
            obj = json.loads(candidate)
        except json.JSONDecodeError as exc:
            return None, f"fenced JSON block did not parse: {exc}"
        if isinstance(obj, dict) and "rows" in obj:
            return obj, None
    # Try a bare JSON object.
    decoder = json.JSONDecoder()
    idx = 0
    while idx < len(markdown_text):
        if markdown_text[idx] != "{":
            idx += 1
            continue
        try:
            obj, end = decoder.raw_decode(markdown_text, idx)
        except json.JSONDecodeError:
            idx += 1
            continue
        if isinstance(obj, dict) and "rows" in obj:
            return obj, None
        idx = end
    return None, "no pairing-table JSON object found"


def _has_coverage_paragraph(markdown_text: str) -> bool:
    return any(m.search(markdown_text) for m in COVERAGE_MARKERS)


def _contains_file_line(value: object) -> bool:
    return isinstance(value, str) and bool(FILE_LINE.search(value))


def _has_marker(markdown_text: str, markers: tuple[re.Pattern[str], ...]) -> bool:
    return any(marker.search(markdown_text) for marker in markers)


def _load_evidence_ledger(path_arg: str) -> tuple[dict[str, dict], list[str]]:
    """Load evidence records and verify saved artifacts and their hashes."""
    ledger = Path(path_arg).resolve()
    if not ledger.exists():
        return {}, [f"evidence ledger not found: {ledger}"]
    records: dict[str, dict] = {}
    errors: list[str] = []
    for line_number, line in enumerate(ledger.read_text(encoding="utf-8").splitlines(), 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"evidence ledger line {line_number} is invalid JSON: {exc}")
            continue
        if not isinstance(record, dict):
            errors.append(f"evidence ledger line {line_number} must be an object")
            continue
        evidence_id = record.get("id")
        if not isinstance(evidence_id, str) or not re.fullmatch(r"E[0-9]{6}", evidence_id):
            errors.append(f"evidence ledger line {line_number} has an invalid ID")
            continue
        if evidence_id in records:
            errors.append(f"duplicate evidence ID: {evidence_id}")
            continue
        records[evidence_id] = record
        artifact_name = record.get("artifact")
        if not isinstance(artifact_name, str) or not artifact_name:
            errors.append(f"{evidence_id} has no artifact path")
            continue
        artifact = (ledger.parent / artifact_name).resolve()
        try:
            artifact.relative_to(ledger.parent)
        except ValueError:
            errors.append(f"{evidence_id} artifact escapes the evidence directory")
            continue
        if not artifact.is_file():
            errors.append(f"{evidence_id} artifact is missing: {artifact_name}")
            continue
        artifact_bytes = artifact.read_bytes()
        if len(artifact_bytes) != record.get("artifact_bytes"):
            errors.append(f"{evidence_id} artifact size does not match the ledger")
        if hashlib.sha256(artifact_bytes).hexdigest() != record.get("artifact_sha256"):
            errors.append(f"{evidence_id} artifact hash does not match the ledger")
    return records, errors


def _valid_evidence_ids(value: object, records: dict[str, dict]) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(evidence_id, str)
        and evidence_id in records
        and records[evidence_id].get("truncated") is False
        and records[evidence_id].get("timed_out") is False
        and type(records[evidence_id].get("exit_code")) is int
        and records[evidence_id].get("exit_code") in (0, 1)
        for evidence_id in value
    )


def _cites_source_read(value: object, records: dict[str, dict]) -> bool:
    return (
        isinstance(value, list)
        and any(
            isinstance(evidence_id, str)
            and evidence_id in records
            and records[evidence_id].get("kind") == "read"
            and records[evidence_id].get("exit_code") == 0
            and records[evidence_id].get("truncated") is False
            for evidence_id in value
        )
    )


def _artifact_contains(record: dict, evidence_root: Path, text: str) -> bool:
    artifact_name = record.get("artifact")
    if not isinstance(artifact_name, str):
        return False
    try:
        artifact = (evidence_root / artifact_name).resolve()
        artifact.relative_to(evidence_root.resolve())
        return text in artifact.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return False


def _valid_absence_searches(value: object, records: dict[str, dict]) -> bool:
    """Require two distinct captured zero-match searches."""
    if not isinstance(value, list):
        return False
    searches: set[tuple[str, tuple[str, ...], tuple[str, ...], str]] = set()
    for search in value:
        if not isinstance(search, dict):
            continue
        evidence_id = search.get("evidence_id")
        record = records.get(evidence_id) if isinstance(evidence_id, str) else None
        query = record.get("query") if isinstance(record, dict) else None
        paths = record.get("paths") if isinstance(record, dict) else None
        globs = record.get("globs") if isinstance(record, dict) else None
        cwd = record.get("cwd") if isinstance(record, dict) else None
        if (
            isinstance(record, dict)
            and record.get("kind") == "search"
            and type(record.get("exit_code")) is int
            and record.get("exit_code") == 1
            and record.get("timed_out") is False
            and record.get("truncated") is False
            and type(record.get("artifact_bytes")) is int
            and record.get("artifact_bytes") == 0
            and isinstance(query, str)
            and query.strip()
            and isinstance(paths, list)
            and all(isinstance(path, str) for path in paths)
            and isinstance(globs, list)
            and all(isinstance(glob, str) for glob in globs)
            and isinstance(cwd, str)
        ):
            # Re-running the same empty search does not constitute a
            # second absence check. Different paths or globs may test
            # distinct slices of the surface.
            searches.add((query.strip(), tuple(paths), tuple(globs), cwd))
    return len(searches) >= 2


def _validate_schema(obj: dict, evidence_records: dict[str, dict], evidence_root: Path) -> list[str]:
    """Validate obj against pairing-table.schema.json (no external dep).

    A minimal but complete check: required fields, status enum,
    file_line pattern. Keeps the script stdlib-only.
    """
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["pairing-table top-level must be an object"]

    for required in ("rows", "coverage_paragraph_present", "class_coverage", "work_queue", "guard_checks"):
        if required not in obj:
            errors.append(f"missing required field: {required}")

    if "rows" in obj:
        rows = obj["rows"]
        if not isinstance(rows, list):
            errors.append("rows must be a list")
        else:
            for i, row in enumerate(rows):
                if not isinstance(row, dict):
                    errors.append(f"rows[{i}] must be an object")
                    continue
                for required in ("category", "trust_source", "trust_consumer", "attacker_reach", "status", "file_line", "rationale", "evidence_ids"):
                    if required not in row:
                        errors.append(f"rows[{i}] missing required field: {required}")
                if not isinstance(row.get("category"), str) or row.get("category") not in REQUIRED_CATEGORIES | {"other"}:
                    errors.append(f"rows[{i}].category is not a recognised category: {row.get('category')!r}")
                for field in ("trust_source", "trust_consumer", "attacker_reach", "rationale"):
                    if not isinstance(row.get(field), str) or not row[field].strip():
                        errors.append(f"rows[{i}].{field} must be non-empty")
                if not isinstance(row.get("status"), str) or row.get("status") not in {"upgraded", "DISPROVED", "NEEDS-RUNTIME"}:
                    errors.append(
                        f"rows[{i}].status must be one of upgraded / DISPROVED / NEEDS-RUNTIME, got {row.get('status')!r}"
                    )
                fl = row.get("file_line") or ""
                if not isinstance(fl, str) or not re.match(r"^.+:[0-9]+(-[0-9]+)?$", fl):
                    errors.append(
                        f"rows[{i}].file_line must be 'file:line' or 'file:start-end', got {fl!r}"
                    )
                if row.get("status") == "DISPROVED" and not _contains_file_line(row.get("disproof_evidence")):
                    errors.append(f"rows[{i}].DISPROVED requires disproof_evidence with a file:line reference")
                if not _valid_evidence_ids(row.get("evidence_ids"), evidence_records):
                    errors.append(f"rows[{i}] must cite existing evidence_ids")
                elif not _cites_source_read(row.get("evidence_ids"), evidence_records):
                    errors.append(f"rows[{i}] must cite a captured source read")

    coverage = obj.get("class_coverage")
    coverage_status_by_category: dict[str, str] = {}
    if not isinstance(coverage, list):
        errors.append("class_coverage must be a list")
    else:
        seen: set[str] = set()
        for i, entry in enumerate(coverage):
            if not isinstance(entry, dict):
                errors.append(f"class_coverage[{i}] must be an object")
                continue
            category = entry.get("category")
            if not isinstance(category, str) or category not in REQUIRED_CATEGORIES:
                errors.append(f"class_coverage[{i}].category is not a required baseline category: {category!r}")
            elif category in seen:
                errors.append(f"class_coverage contains duplicate category {category!r}")
            else:
                seen.add(category)
                coverage_status_by_category[category] = entry.get("status", "")
            statuses = {"NOT_CHECKED", "IN_PROGRESS", "HUNTED", "N/A", "NEEDS-RUNTIME"}
            if not isinstance(entry.get("status"), str) or entry.get("status") not in statuses:
                errors.append(f"class_coverage[{i}].status must be NOT_CHECKED / IN_PROGRESS / HUNTED / N/A / NEEDS-RUNTIME")
            if not isinstance(entry.get("strategy"), str) or not entry["strategy"].strip():
                errors.append(f"class_coverage[{i}].strategy must be non-empty")
            evidence = entry.get("evidence")
            if not isinstance(evidence, list) or not all(isinstance(x, str) and x.strip() for x in evidence):
                errors.append(f"class_coverage[{i}].evidence must be a list of non-empty evidence notes")
            if entry.get("status") == "HUNTED":
                if isinstance(evidence, list) and not any(_contains_file_line(x) for x in evidence):
                    errors.append(f"class_coverage[{i}] HUNTED requires at least one evidence file:line")
                if not _valid_evidence_ids(entry.get("evidence_ids"), evidence_records):
                    errors.append(f"class_coverage[{i}] HUNTED requires existing evidence_ids")
                elif not _cites_source_read(entry.get("evidence_ids"), evidence_records):
                    errors.append(f"class_coverage[{i}] HUNTED must cite a captured source read")
            elif entry.get("status") == "N/A":
                searches = entry.get("absence_searches")
                if not _valid_absence_searches(searches, evidence_records):
                    errors.append(f"class_coverage[{i}] N/A requires two distinct captured zero-match searches")
                if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                    errors.append(f"class_coverage[{i}] N/A requires a non-empty reason")
                search_ids = [s.get("evidence_id") for s in searches if isinstance(s, dict) and isinstance(s.get("evidence_id"), str)] if isinstance(searches, list) else []
                if not _valid_evidence_ids(entry.get("evidence_ids"), evidence_records) or not set(search_ids).issubset(set(entry.get("evidence_ids", []))):
                    errors.append(f"class_coverage[{i}] N/A must cite its captured absence searches in evidence_ids")
            elif entry.get("status") in {"NOT_CHECKED", "IN_PROGRESS", "NEEDS-RUNTIME"}:
                if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                    errors.append(f"class_coverage[{i}] {entry.get('status')} requires a reason and scope limitation")
                cited_ids = entry.get("evidence_ids", [])
                if cited_ids and not _valid_evidence_ids(cited_ids, evidence_records):
                    errors.append(f"class_coverage[{i}] has unknown evidence_ids")
        missing = REQUIRED_CATEGORIES - seen
        if missing:
            errors.append("class_coverage missing required categories: " + ", ".join(sorted(missing)))

    work_queue = obj.get("work_queue")
    queue_by_category: dict[str, list[dict]] = {}
    queue_ids: set[str] = set()
    if not isinstance(work_queue, list) or len(work_queue) < len(REQUIRED_CATEGORIES):
        errors.append("work_queue must contain at least one task for each baseline category")
    else:
        for i, task in enumerate(work_queue):
            if not isinstance(task, dict):
                errors.append(f"work_queue[{i}] must be an object")
                continue
            for field in ("id", "category", "task", "priority", "reason", "budget_unit", "stop_condition", "status", "outcome", "evidence_ids"):
                if field not in task:
                    errors.append(f"work_queue[{i}] missing required field: {field}")
            task_id = task.get("id")
            if not isinstance(task_id, str) or not re.fullmatch(r"W[0-9]+", task_id):
                errors.append(f"work_queue[{i}].id must match W<number>")
            elif task_id in queue_ids:
                errors.append(f"duplicate work_queue id: {task_id}")
            else:
                queue_ids.add(task_id)
            category = task.get("category")
            if not isinstance(category, str) or category not in REQUIRED_CATEGORIES | {"other", "final_review"}:
                errors.append(f"work_queue[{i}].category is not recognised: {category!r}")
            else:
                queue_by_category.setdefault(category, []).append(task)
            for field in ("task", "reason", "budget_unit", "stop_condition", "outcome"):
                if not isinstance(task.get(field), str) or not task[field].strip():
                    errors.append(f"work_queue[{i}].{field} must be non-empty")
            priority = task.get("priority")
            if not isinstance(priority, str) or priority not in ("high", "medium", "low"):
                errors.append(f"work_queue[{i}].priority must be high / medium / low")
            status = task.get("status")
            if not isinstance(status, str) or status not in ("completed", "deferred"):
                errors.append(f"work_queue[{i}].status must be completed or deferred before Report")
            evidence_ids = task.get("evidence_ids")
            if not isinstance(evidence_ids, list):
                errors.append(f"work_queue[{i}].evidence_ids must be a list")
            elif status == "completed" and not _valid_evidence_ids(evidence_ids, evidence_records):
                errors.append(f"work_queue[{i}] completed task must cite existing evidence_ids")
            elif evidence_ids and not _valid_evidence_ids(evidence_ids, evidence_records):
                errors.append(f"work_queue[{i}] cites unknown or incomplete evidence_ids")

        for category in REQUIRED_CATEGORIES:
            if category not in queue_by_category:
                errors.append(f"work_queue missing baseline category task: {category}")
                continue
            coverage_status = coverage_status_by_category.get(category)
            required_task_status = "completed" if coverage_status in ("HUNTED", "N/A") else "deferred"
            if not any(task.get("status") == required_task_status for task in queue_by_category[category]):
                errors.append(
                    f"work_queue category {category} needs a {required_task_status} task to match coverage status {coverage_status!r}"
                )
        final_review_tasks = queue_by_category.get("final_review", [])
        if not any(task.get("status") == "completed" for task in final_review_tasks):
            errors.append("work_queue needs a completed final_review task before Report")

    guards = obj.get("guard_checks")
    if not isinstance(guards, list) or not guards:
        errors.append("guard_checks must be a non-empty list; use a none_found record with two searches when applicable")
    else:
        for i, guard in enumerate(guards):
            if not isinstance(guard, dict):
                errors.append(f"guard_checks[{i}] must be an object")
                continue
            for field in ("protected_consumer", "guard_location", "expression", "attacker_input_shape", "evaluated_result"):
                if not isinstance(guard.get(field), str) or not guard[field].strip():
                    errors.append(f"guard_checks[{i}].{field} must be non-empty")
            verdict = guard.get("verdict")
            if not isinstance(verdict, str) or verdict not in {"effective", "ineffective", "uncertain", "none_found"}:
                errors.append(f"guard_checks[{i}].verdict must be effective / ineffective / uncertain / none_found")
            if verdict == "none_found":
                searches = guard.get("absence_searches")
                if not _valid_absence_searches(searches, evidence_records):
                    errors.append(f"guard_checks[{i}] none_found requires two distinct captured zero-match searches")
                search_ids = [s.get("evidence_id") for s in searches if isinstance(s, dict) and isinstance(s.get("evidence_id"), str)] if isinstance(searches, list) else []
                if not _valid_evidence_ids(guard.get("evidence_ids"), evidence_records) or not set(search_ids).issubset(set(guard.get("evidence_ids", []))):
                    errors.append(f"guard_checks[{i}] none_found must cite its captured absence searches in evidence_ids")
            elif not _contains_file_line(guard.get("guard_location")):
                errors.append(f"guard_checks[{i}].guard_location must include a file:line reference")
            if not _valid_evidence_ids(guard.get("evidence_ids"), evidence_records):
                errors.append(f"guard_checks[{i}] must cite existing evidence_ids")
            elif verdict != "none_found":
                reads = [evidence_records[evidence_id] for evidence_id in guard["evidence_ids"]]
                if not any(record.get("kind") == "read" for record in reads):
                    errors.append(f"guard_checks[{i}] must cite a captured source read")
                expression = guard.get("expression")
                if isinstance(expression, str) and not any(
                    record.get("kind") == "read"
                    and isinstance(record.get("artifact"), str)
                    and _artifact_contains(record, evidence_root, expression)
                    for record in reads
                ):
                    errors.append(f"guard_checks[{i}] expression was not found in its cited read artifacts")

    if "coverage_paragraph_present" in obj and obj["coverage_paragraph_present"] is not True:
        errors.append("coverage_paragraph_present must be true (Coverage rule)")

    return errors


def validate(text: str, evidence_records: dict[str, dict], evidence_root: Path) -> tuple[int, list[str]]:
    """Validate the given notes-file text. Returns (exit_code, errors)."""
    errors: list[str] = []
    has_coverage = _has_coverage_paragraph(text)
    has_class_coverage = _has_marker(text, CLASS_COVERAGE_MARKERS)
    has_guard_ledger = _has_marker(text, GUARD_LEDGER_MARKERS)
    obj, parse_err = _extract_pairing_table(text)
    if obj is None:
        return 1, [parse_err or "pairing table not found"]
    schema_errors = _validate_schema(obj, evidence_records, evidence_root)
    errors.extend(schema_errors)
    if not has_coverage:
        errors.append(
            "Coverage paragraph not found; add a '## Coverage' section listing the protocol entries reaching each dangerous primitive."
        )
    if not has_class_coverage:
        errors.append("Class Coverage section not found")
    if not has_guard_ledger:
        errors.append("Guard Evaluation Ledger section not found")
    if schema_errors:
        return 2, errors
    if not has_coverage or not has_class_coverage or not has_guard_ledger:
        return 3, errors
    return 0, []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate audit notes against the Synthesize Hard Gate.")
    parser.add_argument("path", nargs="?", help="Path to notes file. Omit to read stdin.")
    parser.add_argument("--evidence-ledger", required=True, help="JSONL ledger created by runtime/evidence_log.py")
    args = parser.parse_args(argv)

    if args.path and args.path != "-":
        text = Path(args.path).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    evidence_records, ledger_errors = _load_evidence_ledger(args.evidence_ledger)
    if ledger_errors:
        for error in ledger_errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    evidence_root = Path(args.evidence_ledger).resolve().parent
    code, errors = validate(text, evidence_records, evidence_root)
    if code == 0:
        print("OK: required pairing, class-coverage, guard-ledger, and Coverage structure present")
        return 0
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
