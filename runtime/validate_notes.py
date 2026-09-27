#!/usr/bin/env python3
"""validate-notes -- structural checks for audit notes.

Validates the pairing table, baseline class-coverage ledger, guard
evaluation ledger, and Coverage section shape described in
schemas/pairing-table.schema.json and SKILL.md.

This is one of three enforcement primitives added after the
React 19 long-chain false-negative incident (post-mortem
2026-09-25). The model is expected to produce the table; this
CLI checks it. If validation fails, Report cannot start.

Usage:

    python runtime/validate_notes.py path/to/notes.md
    python runtime/validate_notes.py -              # stdin

Exit codes:

    0  -- required ledger structure and section markers are present
    1  -- pairing table missing or unparsable
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


def _valid_absence_searches(value: object) -> bool:
    """Require two distinct query/result records, not just two claims."""
    if not isinstance(value, list):
        return False
    queries: set[str] = set()
    for search in value:
        if not isinstance(search, dict):
            continue
        query = search.get("query")
        result = search.get("result")
        if isinstance(query, str) and query.strip() and isinstance(result, str) and result.strip():
            queries.add(query.strip())
    return len(queries) >= 2


def _validate_schema(obj: dict) -> list[str]:
    """Validate obj against pairing-table.schema.json (no external dep).

    A minimal but complete check: required fields, status enum,
    file_line pattern. Keeps the script stdlib-only.
    """
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["pairing-table top-level must be an object"]

    for required in ("rows", "coverage_paragraph_present", "class_coverage", "guard_checks"):
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
                for required in ("category", "trust_source", "trust_consumer", "attacker_reach", "status", "file_line", "rationale"):
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

    coverage = obj.get("class_coverage")
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
            if not isinstance(entry.get("status"), str) or entry.get("status") not in {"HUNTED", "N/A"}:
                errors.append(f"class_coverage[{i}].status must be HUNTED or N/A")
            if not isinstance(entry.get("strategy"), str) or not entry["strategy"].strip():
                errors.append(f"class_coverage[{i}].strategy must be non-empty")
            evidence = entry.get("evidence")
            if not isinstance(evidence, list) or not evidence or not all(isinstance(x, str) and x.strip() for x in evidence):
                errors.append(f"class_coverage[{i}].evidence must be a non-empty list of evidence notes")
            if entry.get("status") == "HUNTED":
                if isinstance(evidence, list) and not any(_contains_file_line(x) for x in evidence):
                    errors.append(f"class_coverage[{i}] HUNTED requires at least one evidence file:line")
            elif entry.get("status") == "N/A":
                searches = entry.get("absence_searches")
                if not _valid_absence_searches(searches):
                    errors.append(f"class_coverage[{i}] N/A requires two distinct absence query/result records")
                if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                    errors.append(f"class_coverage[{i}] N/A requires a non-empty reason")
        missing = REQUIRED_CATEGORIES - seen
        if missing:
            errors.append("class_coverage missing required categories: " + ", ".join(sorted(missing)))

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
                if not _valid_absence_searches(searches):
                    errors.append(f"guard_checks[{i}] none_found requires two distinct absence query/result records")
            elif not _contains_file_line(guard.get("guard_location")):
                errors.append(f"guard_checks[{i}].guard_location must include a file:line reference")

    if "coverage_paragraph_present" in obj and obj["coverage_paragraph_present"] is not True:
        errors.append("coverage_paragraph_present must be true (Coverage rule)")

    return errors


def validate(text: str) -> tuple[int, list[str]]:
    """Validate the given notes-file text. Returns (exit_code, errors)."""
    errors: list[str] = []
    has_coverage = _has_coverage_paragraph(text)
    has_class_coverage = _has_marker(text, CLASS_COVERAGE_MARKERS)
    has_guard_ledger = _has_marker(text, GUARD_LEDGER_MARKERS)
    obj, parse_err = _extract_pairing_table(text)
    if obj is None:
        return 1, [parse_err or "pairing table not found"]
    schema_errors = _validate_schema(obj)
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
    args = parser.parse_args(argv)

    if args.path and args.path != "-":
        text = Path(args.path).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    code, errors = validate(text)
    if code == 0:
        print("OK: required pairing, class-coverage, guard-ledger, and Coverage structure present")
        return 0
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
