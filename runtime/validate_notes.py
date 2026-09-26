#!/usr/bin/env python3
"""validate-notes -- Runtime-side enforcement primitive (A).

Validates that an audit notes file contains a syntactically valid
pairing table conforming to schemas/pairing-table.schema.json and
that the Coverage paragraph rule (SKILL.md) is honored.

This is one of three enforcement primitives added after the
React 19 long-chain false-negative incident (post-mortem
2026-09-25). The model is expected to produce the table; this
CLI checks it. If validation fails, Report cannot start.

Usage:

    python runtime/validate_notes.py path/to/notes.md
    python runtime/validate_notes.py -              # stdin

Exit codes:

    0  -- valid pairing table + coverage paragraph
    1  -- pairing table missing or empty
    2  -- pairing table malformed (schema violation)
    3  -- coverage paragraph marker missing

The validator does NOT judge the correctness of the audit
content. It judges whether the audit wrote what the Hard Gate
requires. Judgment of correctness is the reviewer's job; this
script is the gate.
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


def _validate_schema(obj: dict) -> list[str]:
    """Validate obj against pairing-table.schema.json (no external dep).

    A minimal but complete check: required fields, status enum,
    file_line pattern. Keeps the script stdlib-only.
    """
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["pairing-table top-level must be an object"]

    for required in ("rows", "coverage_paragraph_present"):
        if required not in obj:
            errors.append(f"missing required field: {required}")

    if "rows" in obj:
        rows = obj["rows"]
        if not isinstance(rows, list):
            errors.append("rows must be a list")
        elif len(rows) == 0:
            errors.append("rows must be non-empty (Hard Gate: empty pairing table -> Report blocked)")
        else:
            for i, row in enumerate(rows):
                if not isinstance(row, dict):
                    errors.append(f"rows[{i}] must be an object")
                    continue
                for required in ("trust_source", "trust_consumer", "status", "file_line"):
                    if required not in row:
                        errors.append(f"rows[{i}] missing required field: {required}")
                if row.get("status") not in {"upgraded", "DISPROVED", "NEEDS-RUNTIME"}:
                    errors.append(
                        f"rows[{i}].status must be one of upgraded / DISPROVED / NEEDS-RUNTIME, got {row.get('status')!r}"
                    )
                fl = row.get("file_line") or ""
                if not re.match(r"^.+:[0-9]+(-[0-9]+)?$", fl):
                    errors.append(
                        f"rows[{i}].file_line must be 'file:line' or 'file:start-end', got {fl!r}"
                    )

    if "coverage_paragraph_present" in obj and obj["coverage_paragraph_present"] is not True:
        errors.append("coverage_paragraph_present must be true (Coverage rule)")

    return errors


def validate(text: str) -> tuple[int, list[str]]:
    """Validate the given notes-file text. Returns (exit_code, errors)."""
    errors: list[str] = []
    has_coverage = _has_coverage_paragraph(text)
    obj, parse_err = _extract_pairing_table(text)
    if obj is None:
        return 1, [parse_err or "pairing table not found"]
    schema_errors = _validate_schema(obj)
    errors.extend(schema_errors)
    if not has_coverage:
        errors.append(
            "Coverage paragraph not found; add a '## Coverage' section listing the protocol entries reaching each dangerous primitive."
        )
    if schema_errors:
        return 2, errors
    if not has_coverage:
        return 3, errors
    return 0, []


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate audit notes against the Synthesize Hard Gate.")
    parser.add_argument("path", nargs="?", help="Path to notes file. Omit to read stdin.")
    args = parser.parse_args(argv)

    if args.path:
        text = Path(args.path).read_text(encoding="utf-8")
    else:
        text = sys.stdin.read()

    code, errors = validate(text)
    if code == 0:
        print("OK: pairing table valid + coverage paragraph present")
        return 0
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())