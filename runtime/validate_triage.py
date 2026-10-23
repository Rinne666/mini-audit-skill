#!/usr/bin/env python3
"""validate-triage -- structural validation for a disclosure triage notes file.

Validates the machine-readable triage table embedded in a triage-notes
Markdown file against schemas/triage-table.schema.json, and checks the
evidence ledger that backs it.

This is a structural check, not a judgement. It cannot prove the
maintainer will accept a report, and it cannot prove the premise
classification is correct. It proves that the decisions are recorded,
that each one cites evidence that exists, and that nothing was quietly
left unexamined.

Usage:
    python runtime/validate_triage.py path/to/triage-notes.md \\
        --evidence-ledger path/to/evidence.jsonl

Exit codes:
    0  all structural requirements passed
    1  one or more requirements failed
    2  usage error, or the schema file is missing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "triage-table.schema.json"

DISPOSITIONS = {"send", "rewrite_then_send", "convert_to_hardening"}
PREMISE_KINDS = {
    "attacker_only",
    "requires_operator_decision",
    "requires_ambient_state",
    "requires_third_party_misconfiguration",
}
BOUNDARY_STATES = {"declared_and_violated", "not_declared", "declared_and_consistent"}
DIVERGENCE_STATES = {"present", "absent", "not_applicable"}
QUESTIONS = {"premise", "boundary", "divergence"}
FILE_LINE = re.compile(r"^.+:[0-9]+(-[0-9]+)?$")

# The notes file must visibly enumerate what was checked. These are the
# section headings a reviewer scans to judge coverage.
COVERAGE_MARKERS = (
    re.compile(r"^#{1,4}\s*The Three Questions", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^#{1,4}\s*Premise Ledger", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^#{1,4}\s*Upstream Prior Classification", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^#{1,4}\s*Trust Ladder", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^#{1,4}\s*Send Order", re.IGNORECASE | re.MULTILINE),
)


def _extract_triage_table(markdown_text: str) -> tuple[dict | None, str | None]:
    """Pull the triage-table JSON object out of the notes file.

    Accepts a fenced JSON block (the conventional form) or a bare JSON
    object that carries the required top-level keys.
    """
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
    return None, "no triage-table JSON object found"


def _has_coverage_paragraph(markdown_text: str) -> bool:
    return any(m.search(markdown_text) for m in COVERAGE_MARKERS)


def _load_evidence_ledger(path_arg: str) -> tuple[dict[str, dict], list[str]]:
    """Load evidence records and verify saved artifacts and their hashes."""
    ledger = Path(path_arg).resolve()
    if not ledger.exists():
        return {}, [f"evidence ledger not found: {ledger}"]
    records: dict[str, dict] = {}
    errors: list[str] = []
    for line_number, line in enumerate(ledger.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
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
        if not isinstance(record, dict):
            continue
        query = record.get("query")
        paths = record.get("paths")
        globs = record.get("globs")
        cwd = record.get("cwd")
        if (
            record.get("kind") == "search"
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
            # Re-running the same empty search is not a second check.
            searches.add((query.strip(), tuple(paths), tuple(globs), cwd))
    return len(searches) >= 2


def _validate_rows(obj: dict, records: dict[str, dict]) -> list[str]:
    """Validate the per-finding triage decisions."""
    errors: list[str] = []
    rows = obj.get("rows")
    if not isinstance(rows, list):
        return ["rows must be a list"]
    if not rows:
        return ["rows must not be empty"]

    seen_fingerprints: set[str] = set()
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            errors.append(f"rows[{i}] must be an object")
            continue
        for required in (
            "fingerprint",
            "title",
            "disposition",
            "premise_kind",
            "boundary_state",
            "divergence_state",
            "subject",
            "rationale",
            "evidence_ids",
        ):
            if required not in row:
                errors.append(f"rows[{i}] missing required field: {required}")
        fingerprint = row.get("fingerprint")
        if isinstance(fingerprint, str):
            if fingerprint in seen_fingerprints:
                errors.append(f"rows[{i}] duplicates fingerprint {fingerprint!r}")
            seen_fingerprints.add(fingerprint)
        for field in ("title", "subject", "rationale"):
            value = row.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"rows[{i}].{field} must be non-empty")

        disposition = row.get("disposition")
        if disposition not in DISPOSITIONS:
            errors.append(
                f"rows[{i}].disposition must be one of {sorted(DISPOSITIONS)}, got {disposition!r}"
            )
        premise_kind = row.get("premise_kind")
        if premise_kind not in PREMISE_KINDS:
            errors.append(
                f"rows[{i}].premise_kind must be one of {sorted(PREMISE_KINDS)}, got {premise_kind!r}"
            )
        boundary_state = row.get("boundary_state")
        if boundary_state not in BOUNDARY_STATES:
            errors.append(
                f"rows[{i}].boundary_state must be one of {sorted(BOUNDARY_STATES)}, got {boundary_state!r}"
            )
        divergence_state = row.get("divergence_state")
        if divergence_state not in DIVERGENCE_STATES:
            errors.append(
                f"rows[{i}].divergence_state must be one of {sorted(DIVERGENCE_STATES)}, got {divergence_state!r}"
            )

        # A subject must be an invariant, not a consequence. Reject the
        # common consequence shapes outright: they are what gets a
        # maintainer to argue about deployment instead of the code.
        subject = row.get("subject")
        if isinstance(subject, str):
            lowered = subject.lower()
            for pattern in (
                r"\battacker can\b",
                r"\battacker could\b",
                r"\ballows an attacker\b",
                r"\bcan be exploited\b",
                r"\bleads to\b",
                r"\ballows compromise\b",
            ):
                if re.search(pattern, lowered):
                    errors.append(
                        f"rows[{i}].subject states a consequence, not an invariant: {subject!r}"
                    )
                    break

        # A "send" must survive all three questions.
        if disposition == "send":
            if premise_kind != "attacker_only":
                errors.append(
                    f"rows[{i}] disposition 'send' requires premise_kind 'attacker_only', got {premise_kind!r}"
                )
            if boundary_state == "declared_and_consistent":
                errors.append(
                    f"rows[{i}] disposition 'send' contradicts boundary_state 'declared_and_consistent'"
                )
            if divergence_state != "present":
                errors.append(
                    f"rows[{i}] disposition 'send' requires divergence_state 'present', got {divergence_state!r}"
                )
        if disposition == "convert_to_hardening":
            suggestion = row.get("hardening_suggestion")
            if not isinstance(suggestion, str) or not suggestion.strip():
                errors.append(
                    f"rows[{i}] disposition 'convert_to_hardening' requires a non-empty hardening_suggestion"
                )
        if disposition == "rewrite_then_send":
            if not isinstance(row.get("original_subject"), str) or not row["original_subject"].strip():
                errors.append(
                    f"rows[{i}] disposition 'rewrite_then_send' requires original_subject (the consequence framing it replaced)"
                )

        # A claimed divergence needs both sides cited.
        if divergence_state == "present":
            sides = row.get("divergence_sides")
            if not isinstance(sides, list) or len(sides) < 2:
                errors.append(
                    f"rows[{i}] divergence_state 'present' requires divergence_sides with both sides cited"
                )
            else:
                for j, side in enumerate(sides):
                    if not isinstance(side, dict):
                        errors.append(f"rows[{i}].divergence_sides[{j}] must be an object")
                        continue
                    fl = side.get("file_line")
                    if not isinstance(fl, str) or not FILE_LINE.match(fl):
                        errors.append(
                            f"rows[{i}].divergence_sides[{j}].file_line must be 'file:line', got {fl!r}"
                        )
                    behavior = side.get("behavior")
                    if not isinstance(behavior, str) or not behavior.strip():
                        errors.append(f"rows[{i}].divergence_sides[{j}].behavior must be non-empty")
        elif divergence_state == "absent":
            if not _valid_absence_searches(row.get("divergence_absence_searches"), records):
                errors.append(
                    f"rows[{i}] divergence_state 'absent' requires two distinct captured zero-match searches "
                    f"in divergence_absence_searches"
                )

        if not _valid_evidence_ids(row.get("evidence_ids"), records):
            errors.append(f"rows[{i}] must cite existing evidence_ids")
        elif not _cites_source_read(row.get("evidence_ids"), records):
            errors.append(f"rows[{i}] must cite a captured source read")
    return errors


def _validate_question_coverage(obj: dict, records: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    coverage = obj.get("question_coverage")
    if not isinstance(coverage, list):
        return ["question_coverage must be a list"]
    seen: set[str] = set()
    for i, entry in enumerate(coverage):
        if not isinstance(entry, dict):
            errors.append(f"question_coverage[{i}] must be an object")
            continue
        question = entry.get("question")
        if question not in QUESTIONS:
            errors.append(
                f"question_coverage[{i}].question must be one of {sorted(QUESTIONS)}, got {question!r}"
            )
        elif question in seen:
            errors.append(f"question_coverage contains duplicate question {question!r}")
        else:
            seen.add(question)
        status = entry.get("status")
        if status not in {"HUNTED", "NEEDS-RUNTIME"}:
            errors.append(
                f"question_coverage[{i}].status must be HUNTED or NEEDS-RUNTIME, got {status!r}"
            )
        strategy = entry.get("strategy")
        if not isinstance(strategy, str) or not strategy.strip():
            errors.append(f"question_coverage[{i}].strategy must be non-empty")
        if not _valid_evidence_ids(entry.get("evidence_ids"), records):
            errors.append(f"question_coverage[{i}] must cite existing evidence_ids")
        elif status == "HUNTED" and not _cites_source_read(entry.get("evidence_ids"), records):
            errors.append(f"question_coverage[{i}] HUNTED must cite a captured source read")
    missing = QUESTIONS - seen
    if missing:
        errors.append(f"question_coverage is missing mandatory question(s): {sorted(missing)}")
    return errors


def _validate_work_queue(obj: dict, records: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    queue = obj.get("work_queue")
    if not isinstance(queue, list):
        return ["work_queue must be a list"]
    categories: set[str] = set()
    final_review_done = False
    for i, item in enumerate(queue):
        if not isinstance(item, dict):
            errors.append(f"work_queue[{i}] must be an object")
            continue
        for required in (
            "id",
            "category",
            "task",
            "priority",
            "reason",
            "budget_unit",
            "stop_condition",
            "status",
            "outcome",
            "evidence_ids",
        ):
            if required not in item:
                errors.append(f"work_queue[{i}] missing required field: {required}")
        category = item.get("category")
        if category not in {"premise", "boundary", "divergence", "ordering", "final_review", "other"}:
            errors.append(
                f"work_queue[{i}].category is not a recognised category: {category!r}"
            )
        else:
            categories.add(category)
        status = item.get("status")
        if status not in {"queued", "active", "completed", "deferred"}:
            errors.append(
                f"work_queue[{i}].status must be queued / active / completed / deferred, got {status!r}"
            )
        if status in {"queued", "active"}:
            errors.append(
                f"work_queue[{i}] is {status!r}; every item must be completed or deferred before Deliver"
            )
        if status == "deferred":
            outcome = item.get("outcome")
            if not isinstance(outcome, str) or not outcome.strip():
                errors.append(f"work_queue[{i}] deferred requires an outcome stating the limitation")
        if category == "final_review" and status == "completed":
            final_review_done = True
        if not _valid_evidence_ids(item.get("evidence_ids"), records):
            errors.append(f"work_queue[{i}] must cite existing evidence_ids")
    for required_category in ("premise", "boundary", "divergence"):
        if required_category not in categories:
            errors.append(f"work_queue has no task for the {required_category!r} question")
    if not final_review_done:
        errors.append("work_queue must contain a completed 'final_review' task before Deliver")
    return errors


def _validate_premise_checks(obj: dict, records: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    checks = obj.get("premise_checks")
    if not isinstance(checks, list):
        return ["premise_checks must be a list"]
    if not checks:
        return ["premise_checks must not be empty"]
    for i, check in enumerate(checks):
        if not isinstance(check, dict):
            errors.append(f"premise_checks[{i}] must be an object")
            continue
        for required in ("claim", "location", "expression", "evaluated_result", "verdict", "evidence_ids"):
            if required not in check:
                errors.append(f"premise_checks[{i}] missing required field: {required}")
        location = check.get("location")
        if not isinstance(location, str) or not FILE_LINE.match(location):
            errors.append(
                f"premise_checks[{i}].location must be 'file:line' or 'file:start-end', got {location!r}"
            )
        expression = check.get("expression")
        if isinstance(expression, str) and expression.strip().lower() in {
            "standard check exists",
            "checked",
            "none",
        }:
            errors.append(
                f"premise_checks[{i}].expression must state the exact condition asserted, not {expression!r}"
            )
        verdict = check.get("verdict")
        if verdict not in {"effective", "ineffective", "uncertain", "none_found"}:
            errors.append(
                f"premise_checks[{i}].verdict must be effective / ineffective / uncertain / none_found, got {verdict!r}"
            )
        if not _valid_evidence_ids(check.get("evidence_ids"), records):
            errors.append(f"premise_checks[{i}] must cite existing evidence_ids")
    return errors


def _validate_send_order(obj: dict) -> list[str]:
    errors: list[str] = []
    order = obj.get("send_order")
    if not isinstance(order, list):
        return ["send_order must be a list"]
    if not order:
        return ["send_order must not be empty"]
    positions: set[int] = set()
    for i, entry in enumerate(order):
        if not isinstance(entry, dict):
            errors.append(f"send_order[{i}] must be an object")
            continue
        for required in ("position", "fingerprint", "disposition", "reason"):
            if required not in entry:
                errors.append(f"send_order[{i}] missing required field: {required}")
        position = entry.get("position")
        if not isinstance(position, int) or position < 1:
            errors.append(f"send_order[{i}].position must be a positive integer")
        elif position in positions:
            errors.append(f"send_order has a duplicate position {position}")
        else:
            positions.add(position)
        disposition = entry.get("disposition")
        if disposition not in {"send", "rewrite_then_send"}:
            errors.append(
                f"send_order[{i}].disposition must be send or rewrite_then_send, got {disposition!r}"
            )
        reason = entry.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"send_order[{i}].reason must be non-empty")

    # The first report establishes credibility: it must be chosen for a
    # clean premise, not for the highest severity.
    if order and isinstance(order[0], dict):
        first = order[0]
        if first.get("position") != 1:
            errors.append("send_order[0].position must be 1")
        reason = first.get("reason")
        if isinstance(reason, str) and not reason.strip():
            errors.append("send_order[0].reason must state why this record goes first")

    # Every send_order entry must correspond to a row with a reportable
    # disposition, and every reportable row must appear in the order.
    rows = obj.get("rows")
    if isinstance(rows, list):
        by_fp = {
            r.get("fingerprint"): r
            for r in rows
            if isinstance(r, dict) and isinstance(r.get("fingerprint"), str)
        }
        reportable = {
            fp for fp, r in by_fp.items() if r.get("disposition") in {"send", "rewrite_then_send"}
        }
        ordered = {e.get("fingerprint") for e in order if isinstance(e, dict)}
        for fp in sorted(reportable - ordered):
            errors.append(f"send_order is missing reportable finding {fp!r}")
        for fp in sorted(ordered - reportable):
            errors.append(f"send_order references {fp!r}, which is not a reportable row")
    return errors


def _validate_channel(obj: dict) -> list[str]:
    errors: list[str] = []
    channel = obj.get("channel")
    if not isinstance(channel, dict):
        return ["channel must be an object"]
    name = channel.get("name")
    if not isinstance(name, str) or not name.strip():
        errors.append("channel.name must be non-empty")
    reason = channel.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        errors.append("channel.reason must state why this channel was chosen")
    return errors


def validate(text: str, records: dict[str, dict]) -> tuple[int, list[str]]:
    errors: list[str] = []
    obj, extract_error = _extract_triage_table(text)
    if obj is None:
        return 1, [extract_error or "triage table could not be extracted"]

    for required in (
        "rows",
        "coverage_paragraph_present",
        "question_coverage",
        "work_queue",
        "premise_checks",
        "send_order",
        "channel",
    ):
        if required not in obj:
            errors.append(f"missing required field: {required}")

    if obj.get("coverage_paragraph_present") is not True:
        errors.append("coverage_paragraph_present must be true")
    if not _has_coverage_paragraph(text):
        errors.append(
            "notes file has no visible coverage section (expected headings: "
            "Trust Ladder, Upstream Prior Classification, The Three Questions, "
            "Premise Ledger, Send Order)"
        )

    errors.extend(_validate_rows(obj, records))
    errors.extend(_validate_question_coverage(obj, records))
    errors.extend(_validate_work_queue(obj, records))
    errors.extend(_validate_premise_checks(obj, records))
    errors.extend(_validate_send_order(obj))
    errors.extend(_validate_channel(obj))

    return (1 if errors else 0), errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a disclosure triage notes file.")
    parser.add_argument("notes", help="path to the triage notes Markdown file")
    parser.add_argument("--evidence-ledger", help="path to the evidence JSONL ledger")
    args = parser.parse_args(argv)

    notes = Path(args.notes)
    if not notes.exists():
        print(f"FAIL: notes file not found: {notes}", file=sys.stderr)
        return 2
    if not SCHEMA_PATH.exists():
        print(f"FAIL: schema missing: {SCHEMA_PATH}", file=sys.stderr)
        return 2

    records: dict[str, dict] = {}
    ledger_errors: list[str] = []
    if args.evidence_ledger:
        records, ledger_errors = _load_evidence_ledger(args.evidence_ledger)
        for err in ledger_errors:
            print(f"FAIL: {err}", file=sys.stderr)
    else:
        print(
            "FAIL: --evidence-ledger is required; a triage decision without cited "
            "evidence is an assertion, not a triage",
            file=sys.stderr,
        )
        return 2

    text = notes.read_text(encoding="utf-8")
    code, errors = validate(text, records)
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    if ledger_errors:
        code = 1
    if code == 0:
        print(
            f"OK: triage structure valid ({len(records)} evidence record(s)); "
            f"dispositions and citations are recorded and internally consistent"
        )
    else:
        print(
            f"FAIL: {len(errors)} triage requirement(s) not met; "
            f"a report built on this state is not ready to send",
            file=sys.stderr,
        )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
