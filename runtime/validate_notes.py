#!/usr/bin/env python3
"""validate-notes -- structural checks for audit notes.

Validates trust pairings, baseline roll-ups, deterministic coverage units,
independent coverage and candidate reviews, budget/run status, guard
evaluations, and required Markdown sections.

This is one of three enforcement primitives added after the
React 19 long-chain false-negative incident (post-mortem
2026-09-25). The model is expected to produce the table; this
CLI checks it against the evidence logger's records. If validation
fails, Report cannot start.

Usage:

    python runtime/validate_notes.py path/to/notes.md --evidence-ledger path/to/evidence.jsonl
    python runtime/validate_notes.py - --evidence-ledger audit/evidence.jsonl

Exit codes:

    0  -- structure and evidence invariants pass; run_status may still be incomplete
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

try:
    from .coverage_id import coverage_id_for
except ImportError:  # Support direct execution as documented in the CLI.
    from coverage_id import coverage_id_for

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


def _source_read_paths(evidence_ids: object, records: dict[str, dict]) -> set[str]:
    if not isinstance(evidence_ids, list):
        return set()
    return {
        record.get("path")
        for evidence_id in evidence_ids
        if isinstance(evidence_id, str)
        and isinstance((record := records.get(evidence_id)), dict)
        and record.get("kind") == "read"
        and record.get("exit_code") == 0
        and record.get("truncated") is False
        and isinstance(record.get("path"), str)
    }


def _cites_any_path(paths: object, evidence_ids: object, records: dict[str, dict]) -> bool:
    return _nonempty_string_list(paths) and bool(set(paths) & _source_read_paths(evidence_ids, records))


def _cites_all_paths(paths: object, evidence_ids: object, records: dict[str, dict]) -> bool:
    return _nonempty_string_list(paths) and set(paths).issubset(_source_read_paths(evidence_ids, records))


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


def _nonempty_string_list(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and item.strip() for item in value
    )


def _valid_ids(value: object, known: set[str]) -> bool:
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        and len(value) == len(set(value))
        and all(item in known for item in value)
    )


def _valid_count(value: object, *, minimum: int = 0) -> bool:
    return type(value) is int and value >= minimum


def _validate_coverage_units(
    value: object,
    class_statuses: dict[str, str],
    evidence_records: dict[str, dict],
) -> tuple[dict[str, dict], dict[str, list[dict]], list[str]]:
    errors: list[str] = []
    units: dict[str, dict] = {}
    candidates: dict[str, list[dict]] = {}
    if not isinstance(value, list) or len(value) < len(REQUIRED_CATEGORIES):
        return units, candidates, ["coverage_units must contain at least four source-derived review units"]

    allowed_statuses = {
        "planned", "in_progress", "covered", "candidate", "blocked",
        "deferred", "not_applicable", "out_of_scope",
    }
    for i, unit in enumerate(value):
        label = f"coverage_units[{i}]"
        if not isinstance(unit, dict):
            errors.append(f"{label} must be an object")
            continue
        required = (
            "coverage_id", "dimensions", "baseline_category", "source_refs",
            "entry_points", "paths_in_scope", "task", "priority", "budget_unit",
            "stop_condition", "wave", "owner_id", "status", "outcome",
            "evidence_ids", "candidate_ids",
        )
        for field in required:
            if field not in unit:
                errors.append(f"{label} missing required field: {field}")
        dimensions = unit.get("dimensions")
        if not isinstance(dimensions, dict):
            errors.append(f"{label}.dimensions must be an object")
            dimensions = {}
        for field in ("surface", "boundary", "subsystem", "attack_class"):
            if not isinstance(dimensions.get(field), str) or not dimensions[field].strip():
                errors.append(f"{label}.dimensions.{field} must be non-empty")
        lifecycle = dimensions.get("lifecycle")
        if lifecycle is not None and (not isinstance(lifecycle, str) or not lifecycle.strip()):
            errors.append(f"{label}.dimensions.lifecycle must be null or non-empty")
        coverage_id = unit.get("coverage_id")
        if isinstance(coverage_id, str):
            try:
                expected_id = coverage_id_for(dimensions)
            except (TypeError, ValueError) as exc:
                expected_id = None
                errors.append(f"{label}.dimensions cannot produce an ID: {exc}")
            if expected_id and coverage_id != expected_id:
                errors.append(f"{label}.coverage_id does not match canonical dimensions (expected {expected_id})")
            if coverage_id in units:
                errors.append(f"duplicate coverage_id: {coverage_id}")
            else:
                units[coverage_id] = unit
        else:
            errors.append(f"{label}.coverage_id must be a string")

        baseline = unit.get("baseline_category")
        if baseline is not None:
            if not isinstance(baseline, str) or baseline not in REQUIRED_CATEGORIES:
                errors.append(f"{label}.baseline_category is not a recognised baseline lens")
            elif dimensions.get("attack_class") != baseline:
                errors.append(f"{label} baseline_category must match dimensions.attack_class")
        elif isinstance(dimensions.get("attack_class"), str) and dimensions.get("attack_class") in REQUIRED_CATEGORIES:
            errors.append(f"{label} must set baseline_category for a baseline attack_class")
        for field in ("source_refs", "entry_points", "paths_in_scope"):
            if not _nonempty_string_list(unit.get(field)):
                errors.append(f"{label}.{field} must be a non-empty list of source-derived references")
        for field in ("task", "budget_unit", "stop_condition", "owner_id", "outcome"):
            if not isinstance(unit.get(field), str) or not unit[field].strip():
                errors.append(f"{label}.{field} must be non-empty")
        if not isinstance(unit.get("priority"), str) or unit.get("priority") not in {"high", "medium", "low"}:
            errors.append(f"{label}.priority must be high / medium / low")
        if not _valid_count(unit.get("wave"), minimum=1):
            errors.append(f"{label}.wave must be a positive integer")
        status = unit.get("status")
        if not isinstance(status, str) or status not in allowed_statuses:
            errors.append(f"{label}.status is not a recognised coverage status")
            status = ""
        evidence_ids = unit.get("evidence_ids")
        if not isinstance(evidence_ids, list):
            errors.append(f"{label}.evidence_ids must be a list")
            evidence_ids = []
        elif evidence_ids and not _valid_evidence_ids(evidence_ids, evidence_records):
            errors.append(f"{label} cites unknown or incomplete evidence_ids")
        elif status in {"covered", "candidate"}:
            if not _valid_evidence_ids(evidence_ids, evidence_records):
                errors.append(f"{label} {status} requires existing evidence_ids")
            elif not _cites_source_read(evidence_ids, evidence_records):
                errors.append(f"{label} {status} must cite a captured source read")
            elif not _cites_any_path(unit.get("paths_in_scope"), evidence_ids, evidence_records):
                errors.append(f"{label} must cite a source read from at least one paths_in_scope entry")
        candidate_ids = unit.get("candidate_ids")
        if (
            not isinstance(candidate_ids, list)
            or not all(isinstance(candidate_id, str) for candidate_id in candidate_ids)
            or len(candidate_ids) != len(set(candidate_ids))
            or not all(re.fullmatch(r"C[0-9]+", candidate_id) for candidate_id in candidate_ids)
        ):
            errors.append(f"{label}.candidate_ids must be a list of unique C<number> IDs")
            candidate_ids = []
        if status == "candidate" and not candidate_ids:
            errors.append(f"{label} candidate status requires candidate_ids")
        if status != "candidate" and candidate_ids:
            errors.append(f"{label} may list candidate_ids only when status is candidate")
        for candidate_id in candidate_ids:
            candidates.setdefault(candidate_id, []).append(unit)
        if status == "not_applicable":
            searches = unit.get("absence_searches")
            if not _valid_absence_searches(searches, evidence_records):
                errors.append(f"{label} not_applicable requires two distinct captured zero-match searches")
            search_ids = [s.get("evidence_id") for s in searches if isinstance(s, dict) and isinstance(s.get("evidence_id"), str)] if isinstance(searches, list) else []
            if not _valid_evidence_ids(evidence_ids, evidence_records) or not set(search_ids).issubset(set(evidence_ids)):
                errors.append(f"{label} not_applicable must cite both absence searches")
        if status in {"planned", "in_progress", "blocked", "deferred", "out_of_scope"}:
            if not isinstance(unit.get("limitation"), str) or not unit["limitation"].strip():
                errors.append(f"{label} {status} requires an explicit limitation")
        if status in {"covered", "candidate"} and not evidence_ids:
            errors.append(f"{label} completed coverage needs evidence")

    active_units = [unit.get("coverage_id") for unit in units.values() if unit.get("status") == "in_progress"]
    if len(active_units) > 1:
        errors.append("at most one coverage unit may be in_progress at a time")

    for category in REQUIRED_CATEGORIES:
        matching = [unit for unit in units.values() if unit.get("baseline_category") == category]
        if not matching:
            errors.append(f"coverage_units missing baseline category: {category}")
            continue
        rollup = class_statuses.get(category)
        statuses = [unit.get("status") if isinstance(unit.get("status"), str) else "" for unit in matching]
        if rollup == "N/A" and any(status != "not_applicable" for status in statuses):
            errors.append(f"class_coverage {category} is N/A but not all its units are not_applicable")
        if rollup == "HUNTED":
            if not any(status in {"covered", "candidate"} for status in statuses):
                errors.append(f"class_coverage {category} is HUNTED without a covered or candidate unit")
            if any(status in {"planned", "in_progress", "blocked", "deferred", "out_of_scope"} for status in statuses):
                errors.append(f"class_coverage {category} is HUNTED while a unit remains open")
    return units, candidates, errors


def _validate_coverage_reviews(
    value: object,
    units: dict[str, dict],
    evidence_records: dict[str, dict],
    *,
    require_complete: bool,
) -> tuple[list[str], bool, bool, set[str]]:
    errors: list[str] = []
    post_wave_reviewers: set[str] = set()
    independent_reviewers: set[str] = set()
    wave_independence: dict[int, bool] = {}
    if not isinstance(value, list):
        return ["coverage_reviews must be a list"], False, False, independent_reviewers
    if not value and require_complete:
        return ["complete run requires post-wave critics and a final-clean review"], False, False, independent_reviewers
    ids = set(units)
    seen_review_ids: set[str] = set()
    seen_waves: set[int] = set()
    final_reviews: list[dict] = []
    for i, review in enumerate(value):
        label = f"coverage_reviews[{i}]"
        if not isinstance(review, dict):
            errors.append(f"{label} must be an object")
            continue
        for field in ("review_id", "review_type", "wave", "reviewer_id", "independent", "scope_reviewed", "reviewed_coverage_ids", "decision", "new_coverage_ids", "evidence_ids"):
            if field not in review:
                errors.append(f"{label} missing required field: {field}")
        review_id = review.get("review_id")
        if not isinstance(review_id, str) or not re.fullmatch(r"CR[0-9]+", review_id):
            errors.append(f"{label}.review_id must match CR<number>")
        elif review_id in seen_review_ids:
            errors.append(f"duplicate coverage review ID: {review_id}")
        else:
            seen_review_ids.add(review_id)
        if not isinstance(review.get("reviewer_id"), str) or not review["reviewer_id"].strip():
            errors.append(f"{label}.reviewer_id must be non-empty")
        if not isinstance(review.get("scope_reviewed"), str) or not review["scope_reviewed"].strip():
            errors.append(f"{label}.scope_reviewed must describe what was challenged")
        reviewed = review.get("reviewed_coverage_ids")
        if not _valid_ids(reviewed, ids) or not reviewed:
            errors.append(f"{label}.reviewed_coverage_ids must be unique known coverage IDs")
            reviewed = []
        new_ids = review.get("new_coverage_ids")
        if not _valid_ids(new_ids, ids):
            errors.append(f"{label}.new_coverage_ids must be unique known coverage IDs")
            new_ids = []
        decision = review.get("decision")
        if not isinstance(decision, str) or decision not in {"clean", "gaps_found"}:
            errors.append(f"{label}.decision must be clean or gaps_found")
        if decision == "clean" and new_ids:
            errors.append(f"{label} clean review cannot list new coverage units")
        if decision == "gaps_found" and not new_ids:
            errors.append(f"{label} gaps_found review must create and link new coverage units")
        evidence = review.get("evidence_ids")
        if not _valid_evidence_ids(evidence, evidence_records):
            errors.append(f"{label} must cite existing evidence_ids")
        elif not _cites_source_read(evidence, evidence_records):
            errors.append(f"{label} must cite a captured source read")

        review_type = review.get("review_type")
        if review_type == "post_wave":
            wave = review.get("wave")
            if not _valid_count(wave, minimum=1):
                errors.append(f"{label}.wave must be a positive integer for post_wave review")
                continue
            if wave in seen_waves:
                errors.append(f"wave {wave} has duplicate post-wave reviews")
            seen_waves.add(wave)
            expected = {coverage_id for coverage_id, unit in units.items() if unit.get("wave") == wave}
            if not expected:
                errors.append(f"{label} references a wave with no coverage units")
            if set(reviewed) != expected:
                errors.append(f"{label} must review every and only coverage unit assigned to wave {wave}")
            owners = {units[cid].get("owner_id") for cid in reviewed if cid in units and isinstance(units[cid].get("owner_id"), str)}
            reviewer = review.get("reviewer_id")
            independent = review.get("independent")
            if not isinstance(independent, bool):
                errors.append(f"{label}.independent must be a boolean")
                independent = False
            if independent and isinstance(reviewer, str) and reviewer in owners:
                errors.append(f"{label} claims independence but reviewer is a wave {wave} unit owner")
            wave_independence[wave] = independent
            if independent and isinstance(reviewer, str):
                post_wave_reviewers.add(reviewer)
                independent_reviewers.add(reviewer)
            if any(
                isinstance(units[cid].get("status"), str)
                and units[cid].get("status") in {"planned", "in_progress"}
                for cid in reviewed if cid in units
            ):
                errors.append(f"{label} cannot review a wave with planned or in_progress units")
            for new_id in new_ids:
                if new_id in units and not _valid_count(units[new_id].get("wave"), minimum=wave + 1):
                    errors.append(f"{label} new unit {new_id} must be assigned to a later wave")
        elif review_type == "final_clean":
            final_reviews.append(review)
            if review.get("wave") is not None:
                errors.append(f"{label}.wave must be null for final_clean review")
            if set(reviewed) != ids:
                errors.append(f"{label} final_clean review must cover every current coverage unit")
            if decision != "clean" or new_ids:
                errors.append(f"{label} final_clean must be clean with no new coverage units")
            all_owners = {unit.get("owner_id") for unit in units.values() if isinstance(unit.get("owner_id"), str)}
            reviewer = review.get("reviewer_id")
            independent = review.get("independent")
            if not isinstance(independent, bool):
                errors.append(f"{label}.independent must be a boolean")
                independent = False
            if independent and isinstance(reviewer, str) and reviewer in all_owners:
                errors.append(f"{label} claims independence but reviewer is a unit owner")
            if independent and isinstance(reviewer, str) and reviewer in post_wave_reviewers:
                errors.append(f"{label} independent reviewer must differ from independent post-wave critics")
            if independent and isinstance(reviewer, str):
                independent_reviewers.add(reviewer)
        else:
            errors.append(f"{label}.review_type must be post_wave or final_clean")

    actual_waves = {unit.get("wave") for unit in units.values() if _valid_count(unit.get("wave"), minimum=1)}
    if require_complete and actual_waves != seen_waves:
        errors.append("every coverage wave must have exactly one post_wave critic")
    if len(final_reviews) > 1:
        errors.append("coverage_reviews may contain only one final_clean review")
    final_clean_independent = bool(final_reviews and final_reviews[0].get("independent") is True)
    if final_clean_independent:
        final_reviewer = final_reviews[0].get("reviewer_id")
        if isinstance(final_reviewer, str) and final_reviewer in post_wave_reviewers:
            errors.append("final_clean reviewer must be different from every independent post-wave critic")
    all_waves_independent = actual_waves == set(wave_independence) and all(wave_independence.values())
    return errors, final_clean_independent, all_waves_independent, independent_reviewers


def _validate_candidate_reviews(
    value: object,
    candidates: dict[str, list[dict]],
    units: dict[str, dict],
    coverage_reviewers: set[str],
    evidence_records: dict[str, dict],
    *,
    require_complete: bool,
) -> tuple[list[str], bool]:
    errors: list[str] = []
    if not isinstance(value, list):
        return ["candidate_reviews must be a list"], False
    seen: set[str] = set()
    complete = True
    for i, review in enumerate(value):
        label = f"candidate_reviews[{i}]"
        if not isinstance(review, dict):
            errors.append(f"{label} must be an object")
            continue
        for field in ("candidate_id", "claim", "source_refs", "verdict", "verifier_id", "independent", "reviewed_paths", "disproof_attempt", "unresolved", "evidence_ids"):
            if field not in review:
                errors.append(f"{label} missing required field: {field}")
        candidate_id = review.get("candidate_id")
        if not isinstance(candidate_id, str) or not re.fullmatch(r"C[0-9]+", candidate_id):
            errors.append(f"{label}.candidate_id must match C<number>")
            continue
        if candidate_id in seen:
            errors.append(f"duplicate candidate review: {candidate_id}")
        seen.add(candidate_id)
        if candidate_id not in candidates:
            errors.append(f"{label} is not linked from any candidate coverage unit")
        for field in ("claim", "verifier_id", "disproof_attempt"):
            if not isinstance(review.get(field), str) or not review[field].strip():
                errors.append(f"{label}.{field} must be non-empty")
        for field in ("source_refs", "reviewed_paths"):
            if not _nonempty_string_list(review.get(field)):
                errors.append(f"{label}.{field} must be a non-empty list")
        verdict = review.get("verdict")
        if not isinstance(verdict, str) or verdict not in {"confirmed", "needs_validation", "rejected"}:
            errors.append(f"{label}.verdict must be confirmed / needs_validation / rejected")
        unresolved = review.get("unresolved")
        if verdict == "needs_validation":
            complete = False
            if not isinstance(unresolved, str) or not unresolved.strip():
                errors.append(f"{label} needs_validation requires an unresolved condition")
        elif unresolved not in ("", None):
            errors.append(f"{label} terminal verdict must not retain unresolved conditions")
        verifier = review.get("verifier_id")
        candidate_owners = {unit.get("owner_id") for unit in candidates.get(candidate_id, []) if isinstance(unit.get("owner_id"), str)}
        independent = review.get("independent")
        if not isinstance(independent, bool):
            errors.append(f"{label}.independent must be a boolean")
            independent = False
        if independent and isinstance(verifier, str) and (verifier in candidate_owners or verifier in coverage_reviewers):
            errors.append(f"{label} claims independence but verifier is a candidate hunter or coverage critic")
            complete = False
        if not independent or not isinstance(verdict, str) or verdict not in {"confirmed", "rejected"}:
            complete = False
        evidence = review.get("evidence_ids")
        if not _valid_evidence_ids(evidence, evidence_records):
            errors.append(f"{label} must cite existing evidence_ids")
        elif not _cites_source_read(evidence, evidence_records):
            errors.append(f"{label} must cite a captured source read")
        elif not _cites_all_paths(review.get("reviewed_paths"), evidence, evidence_records):
            errors.append(f"{label}.reviewed_paths must each match a captured source read path")
    missing = set(candidates) - seen
    if missing:
        complete = False
        if require_complete:
            errors.append("candidate IDs lack independent review records: " + ", ".join(sorted(missing)))
    return errors, complete


def _validate_run_gate(
    obj: dict,
    units: dict[str, dict],
    class_statuses: dict[str, str],
    final_clean_present: bool,
    all_waves_independent: bool,
    candidates_complete: bool,
) -> list[str]:
    errors: list[str] = []
    status = obj.get("run_status")
    reasons = obj.get("incomplete_reasons")
    if not isinstance(status, str) or status not in {"complete", "incomplete"}:
        errors.append("run_status must be complete or incomplete")
    if not isinstance(reasons, list) or not all(isinstance(reason, str) and reason.strip() for reason in reasons):
        errors.append("incomplete_reasons must be a list of non-empty strings")
        reasons = []
    if status == "incomplete" and not reasons:
        errors.append("incomplete run requires explicit incomplete_reasons")
    budget = obj.get("budget")
    if not isinstance(budget, dict):
        errors.append("budget must be an object")
    else:
        if not isinstance(budget.get("unit"), str) or not budget["unit"].strip():
            errors.append("budget.unit must name the tracked unit")
        for field, minimum in (("max_units", 1), ("spent_units", 0), ("review_reserve_units", 1), ("candidate_review_reserve_units", 0)):
            if not _valid_count(budget.get(field), minimum=minimum):
                errors.append(f"budget.{field} must be an integer >= {minimum}")
        if all(_valid_count(budget.get(key)) for key in ("max_units", "spent_units", "review_reserve_units", "candidate_review_reserve_units")):
            if budget["spent_units"] > budget["max_units"]:
                errors.append("budget spent_units exceeds max_units")
            if budget["max_units"] < budget["review_reserve_units"] + budget["candidate_review_reserve_units"]:
                errors.append("budget max_units must cover the reserved review allocations")
            if any(unit.get("candidate_ids") for unit in units.values()) and budget["candidate_review_reserve_units"] < 1:
                errors.append("candidate units require a reserved candidate-review budget")
    if status != "complete":
        return errors

    open_statuses = {"planned", "in_progress", "blocked", "deferred", "out_of_scope"}
    open_units = [
        coverage_id for coverage_id, unit in units.items()
        if isinstance(unit.get("status"), str) and unit.get("status") in open_statuses
    ]
    if open_units:
        errors.append("complete run has open coverage units: " + ", ".join(sorted(open_units)))
    if any(isinstance(value, str) and value in {"NOT_CHECKED", "IN_PROGRESS", "NEEDS-RUNTIME"} for value in class_statuses.values()):
        errors.append("complete run has an incomplete baseline class_coverage status")
    if not final_clean_present:
        errors.append("complete run requires an independent final_clean coverage review")
    if not all_waves_independent:
        errors.append("complete run requires an independent post_wave critic for every wave")
    if not candidates_complete:
        errors.append("complete run requires terminal independent dispositions for all candidates")
    if reasons:
        errors.append("complete run must have an empty incomplete_reasons list")
    return errors


def _validate_schema(obj: dict, evidence_records: dict[str, dict], evidence_root: Path) -> list[str]:
    """Validate obj against pairing-table.schema.json (no external dep).

    Type-specific structural checks for the required contract. Keeps the
    script stdlib-only; it does not execute JSON Schema Draft 7 validation.
    """
    errors: list[str] = []
    if not isinstance(obj, dict):
        return ["pairing-table top-level must be an object"]

    for required in ("rows", "coverage_paragraph_present", "class_coverage", "coverage_units", "coverage_reviews", "candidate_reviews", "run_status", "budget", "incomplete_reasons", "guard_checks"):
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
            elif isinstance(entry.get("status"), str) and entry.get("status") in {"NOT_CHECKED", "IN_PROGRESS", "NEEDS-RUNTIME"}:
                if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                    errors.append(f"class_coverage[{i}] {entry.get('status')} requires a reason and scope limitation")
                cited_ids = entry.get("evidence_ids", [])
                if cited_ids and not _valid_evidence_ids(cited_ids, evidence_records):
                    errors.append(f"class_coverage[{i}] has unknown evidence_ids")
        missing = REQUIRED_CATEGORIES - seen
        if missing:
            errors.append("class_coverage missing required categories: " + ", ".join(sorted(missing)))

    units_by_id, candidates_by_id, unit_errors = _validate_coverage_units(
        obj.get("coverage_units"), coverage_status_by_category, evidence_records
    )
    errors.extend(unit_errors)
    review_errors, final_clean_present, all_waves_independent, post_wave_reviewers = _validate_coverage_reviews(
        obj.get("coverage_reviews"), units_by_id, evidence_records,
        require_complete=obj.get("run_status") == "complete"
    )
    errors.extend(review_errors)
    candidate_errors, candidates_complete = _validate_candidate_reviews(
        obj.get("candidate_reviews"), candidates_by_id, units_by_id,
        post_wave_reviewers, evidence_records,
        require_complete=obj.get("run_status") == "complete"
    )
    errors.extend(candidate_errors)
    errors.extend(_validate_run_gate(
        obj, units_by_id, coverage_status_by_category,
        final_clean_present, all_waves_independent, candidates_complete
    ))

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
            "Coverage paragraph not found; add a '## Coverage' section listing the protocol entries reaching each dangerous primitive and link them to coverage-unit IDs."
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
        obj, _ = _extract_pairing_table(text)
        run_status = obj.get("run_status", "unknown") if isinstance(obj, dict) else "unknown"
        print(f"OK: structural checks passed (run_status={run_status}); this does not certify semantic completeness")
        return 0
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
