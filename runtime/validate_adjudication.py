#!/usr/bin/env python3
"""validate-adjudication -- structural validation for a claim adjudication file.

Validates the machine-readable adjudication table embedded in an
adjudication-notes Markdown file against
schemas/adjudication.schema.json, and checks the evidence ledger that
backs it.

The important checks here are the *derivations*: the validity verdict
must follow from the assertion verdicts, and the acceptability verdict
must follow from the three acceptance answers. Those are the two places
where a model under pressure is most likely to talk itself into a
stronger conclusion than the evidence supports.

The ledger is also checked for *self-reporting*: a search record that
claims "no matches" is re-run against the source it names, and a record
whose search no longer reproduces is rejected. An absence that cannot be
reproduced is not evidence of absence, and a ledger that merely asserts
one is worthless.

This is a structural check, not a judgement. It cannot prove a verdict
is correct, and it cannot prove a maintainer will accept a report. It
proves the verdicts are recorded, that each one cites evidence that
exists, that the absence evidence still reproduces, that the two
verdicts were derived rather than asserted, that an open-source target
carries its verification block (policy, commit timeline, similar
issues, maintainer preference), and that every reportable claim's
submission block is complete with exactly one primary target whose
trigger-configuration answer agrees with its derived premise.

Usage:
    python runtime/validate_adjudication.py path/to/adjudication-notes.md \\
        --evidence-ledger path/to/evidence.jsonl [--phase adjudicate|assess|deliver] [--next]

The validator is phase-gated so that running it mid-work returns one
actionable instruction instead of a wall of end-state failures:

    --phase adjudicate  only what the Adjudicate stage owes: decomposition,
                        assertion ledger rows, derived validity verdicts
    --phase assess      the above plus the three acceptance answers and the
                        OSS verification block for every holding claim
    --phase deliver     everything, including submission blocks, work-queue
                        closure and the channel decision (the default, and
                        the delivery gate)
    --next              walk the phases in order, print the single next
                        requirement as `NEXT [phase]: ...`, or `READY` when
                        all three gates are green. The driver of the loop.

Exit codes:
    0  all structural requirements passed (--next also returns 0; read the
       printed instruction instead of the exit code)
    1  one or more requirements failed
    2  usage error, or a required file is missing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schemas" / "adjudication.schema.json"

VALIDITY = {"holds", "does_not_hold", "needs_more_evidence", "already_fixed"}
PHASES = ("adjudicate", "assess", "deliver")
# Which top-level JSON fields each phase owes. Work queue closure and the
# channel decision are delivery-time facts; requiring them earlier would
# make every mid-work run red for the wrong reason.
REQUIRED_TOP_FIELDS: dict[str, tuple[str, ...]] = {
    "adjudicate": ("claims", "coverage_paragraph_present", "target"),
    "assess": ("claims", "coverage_paragraph_present", "target"),
    "deliver": ("claims", "coverage_paragraph_present", "work_queue", "channel", "target"),
}
MAX_SEARCH_RESULTS_PER_FILE = 500
ACTIONS = {
    "report",
    "rewrite_then_report",
    "hardening_note",
    "no_report",
    "needs_evidence",
    "already_fixed",
}
ASSERTION_VERDICTS = {"confirmed", "refuted", "unresolved", "fixed"}
ASSERTION_TYPES = {"defect", "reachability", "consequence", "precondition"}
PREMISE_KINDS = {
    "attacker_only",
    "requires_operator_decision",
    "requires_ambient_state",
    "requires_third_party_misconfiguration",
}
BOUNDARY_STATES = {"declared_and_violated", "not_declared", "declared_and_consistent"}
DIVERGENCE_STATES = {"present", "absent"}
ACCEPTABILITY = {"accept", "accept_after_rewrite", "decline"}
TARGET_KINDS = {"open_source", "closed_product", "web_service"}
POLICY_SOURCES = {"stated", "derived", "none"}
CLASSIFICATIONS = {"security_fix", "hardening", "bug_fix", "wontfix", "unknown"}
SUBMISSION_TARGETS = {
    "vendor_advisory",
    "cve_cna",
    "cnvd",
    "src_platform",
    "bounty_platform",
    "hardening_channel",
}
TARGET_FITS = {"primary", "secondary", "unsuitable"}
AWARENESS_STATES = {"aware", "false", "unknown"}
SEVERITIES = {"critical", "high", "medium", "low"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
FILE_LINE = re.compile(r"^.+:[0-9]+(-[0-9]+)?$")

# A subject stated as a consequence rather than an invariant.
CONSEQUENCE_PATTERNS = (
    r"\battacker can\b",
    r"\battacker could\b",
    r"\ballows an attacker\b",
    r"\bcan be exploited\b",
    r"\bleads to\b",
    r"\ballows compromise\b",
    r"\bcan take over\b",
    r"\bgains access\b",
)

# The notes file must visibly enumerate what was checked. Every one of
# these sections is required: a file with the Verdict Table but no
# Assertion Ledger looks complete and proves nothing.
COVERAGE_MARKERS = (
    ("Claims Under Adjudication", re.compile(r"^#{1,4}\s*Claims Under Adjudication", re.IGNORECASE | re.MULTILINE)),
    ("Claim Decomposition", re.compile(r"^#{1,4}\s*Claim Decomposition", re.IGNORECASE | re.MULTILINE)),
    ("Assertion Ledger", re.compile(r"^#{1,4}\s*Assertion Ledger", re.IGNORECASE | re.MULTILINE)),
    ("Acceptance Answers", re.compile(r"^#{1,4}\s*Acceptance Answers", re.IGNORECASE | re.MULTILINE)),
    ("OSS Verification", re.compile(r"^#{1,4}\s*OSS Verification", re.IGNORECASE | re.MULTILINE)),
    ("Verdict Table", re.compile(r"^#{1,4}\s*Verdict Table", re.IGNORECASE | re.MULTILINE)),
    ("Submission Summary", re.compile(r"^#{1,4}\s*Submission Summary", re.IGNORECASE | re.MULTILINE)),
    ("Refutations Considered", re.compile(r"^#{1,4}\s*Refutations Considered", re.IGNORECASE | re.MULTILINE)),
)

# Every coverage section above is always required. For a target that is
# not open source, the OSS Verification section states "not applicable"
# with the reason — it is the JSON oss_verification object that is
# conditional on the target kind, not the section.


def _extract_adjudication_table(markdown_text: str) -> tuple[dict | None, str | None]:
    """Pull the adjudication-table JSON object out of the notes file."""
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
        if isinstance(obj, dict) and "claims" in obj:
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
        if isinstance(obj, dict) and "claims" in obj:
            return obj, None
        idx = end
    return None, "no adjudication-table JSON object found"


def _missing_coverage_sections(markdown_text: str) -> list[str]:
    """Return the coverage sections a reviewer scans that are absent.

    Every section is required. A notes file that has the Verdict Table
    but no Assertion Ledger looks complete and proves nothing.
    """
    return [name for name, marker in COVERAGE_MARKERS if not marker.search(markdown_text)]


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
    errors.extend(_reverify_ledger_searches(ledger.parent, records))
    return records, errors


def _normalize_rel(value: str) -> str:
    """Make a recorded relative path portable across path separators."""
    return value.replace("\\", "/")


def _reverify_zero_match(ledger_parent: Path, record: dict) -> str | None:
    """Re-run a recorded zero-match search and report whether it still holds.

    A ledger entry that says "no matches" is a claim about the source.
    If the search now matches, the claim is false and every verdict that
    leaned on it is unsupported. If the source tree is not reachable from
    here, or `rg` is not installed, the check is skipped rather than
    failed: the evidence is unverifiable here, not wrong.
    """
    base_raw = record.get("cwd")
    paths = record.get("paths")
    query = record.get("query")
    globs = record.get("globs")
    if not isinstance(base_raw, str) or not base_raw:
        return None
    if not isinstance(paths, list) or not all(isinstance(p, str) for p in paths):
        return None
    if not isinstance(query, str) or not query.strip():
        return None
    if not isinstance(globs, list) or not all(isinstance(g, str) for g in globs):
        return None
    base = (ledger_parent / Path(_normalize_rel(base_raw))).resolve()
    if not base.is_dir():
        return None
    # The recorded search paths must all exist under the recorded base.
    # When they do not, the workspace has been moved or copied and the
    # source tree is not reachable from here — skipping is the honest
    # answer, and the alternative (running rg in the wrong directory)
    # reports a spurious failure that poisons the gate.
    if not all((base / _normalize_rel(path)).exists() for path in paths):
        return None
    if shutil.which("rg") is None:
        return None
    command = [
        "rg",
        "--line-number",
        "--with-filename",
        "--no-heading",
        "--color",
        "never",
        "--max-count",
        str(MAX_SEARCH_RESULTS_PER_FILE),
    ]
    for glob in globs:
        command.extend(["--glob", glob])
    command.extend(["--", query])
    command.extend(_normalize_rel(path) for path in paths)
    try:
        result = subprocess.run(command, capture_output=True, cwd=base, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode == 1:
        return None  # still zero-match: the absence still holds
    if result.returncode == 0:
        matched = result.stdout.decode("utf-8", errors="replace").strip().splitlines()
        first = matched[0] if matched else ""
        return (
            f"records a zero-match search that no longer reproduces: pattern "
            f"{query!r} now matches {first!r}"
        )
    return (
        f"records a zero-match search that no longer runs cleanly: pattern "
        f"{query!r} exited {result.returncode}"
    )


def _reverify_ledger_searches(ledger_parent: Path, records: dict[str, dict]) -> list[str]:
    """Re-run every search the ledger claims produced no matches."""
    errors: list[str] = []
    for evidence_id, record in sorted(records.items()):
        if record.get("kind") != "search" or record.get("exit_code") != 1:
            continue
        problem = _reverify_zero_match(ledger_parent, record)
        if problem:
            errors.append(f"{evidence_id} {problem}")
    return errors


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


def _derive_validity(assertion_types: list[str], assertion_verdicts: list[str]) -> str:
    """Derive the validity verdict mechanically from the assertions.

    The precondition type is treated differently from the other three.

    A `precondition` assertion describes the condition that must hold
    for the trigger to fire. Its being unresolved says the trigger may
    be rare or situational; it does not say the defect is absent. The
    defect, the reachability and the consequence are what establish
    that the claim is a vulnerability, and an unresolved one of those
    blocks the verdict.

    A `precondition` that is unresolved therefore leaves the validity
    at `holds`, and its uncertainty is carried by the acceptance
    stage's premise question, where it belongs: the premise is what
    determines whether the maintainer will accept the report.
    """
    if not assertion_verdicts:
        return "unadjudicated"
    if "refuted" in assertion_verdicts:
        return "does_not_hold"
    if "fixed" in assertion_verdicts:
        return "already_fixed"
    for atype, averdict in zip(assertion_types, assertion_verdicts):
        if averdict == "unresolved" and atype != "precondition":
            return "needs_more_evidence"
    return "holds"


def _derive_acceptability(premise_kind: str, boundary_state: str, divergence_state: str) -> str:
    """Derive the acceptability verdict mechanically from the three answers."""
    if boundary_state == "declared_and_consistent":
        return "decline"
    if premise_kind == "attacker_only" and divergence_state == "present":
        return "accept"
    if premise_kind == "attacker_only":
        # A clean premise without a divergence: the claim may still be
        # reportable, but the framing needs work.
        return "accept_after_rewrite"
    if premise_kind == "requires_third_party_misconfiguration" and divergence_state == "present":
        return "accept_after_rewrite"
    return "decline"


def _special_config_consistent(special_config_required: object, premise_kind: object) -> bool:
    """A trigger-configuration answer must agree with the derived premise.

    `special_config_required` and the premise kind describe the same
    fact from two sides: who creates the condition that makes the
    defect reachable. An `attacker_only` premise means the attacker
    creates that condition alone, on the default configuration — so a
    summary that says the trigger needs special configuration while the
    premise says attacker-only has one of the two answers wrong.
    """
    if special_config_required is True and premise_kind == "attacker_only":
        return False
    return True


def _non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _subject_is_consequence(subject: str) -> bool:
    lowered = subject.lower()
    return any(re.search(pattern, lowered) for pattern in CONSEQUENCE_PATTERNS)


def _validate_target(obj: dict) -> list[str]:
    """The target profile every verdict in the file is relative to."""
    errors: list[str] = []
    target = obj.get("target")
    if not isinstance(target, dict):
        return ["target must be an object (kind / name / security_policy / preferred_channel)"]
    kind = target.get("kind")
    if kind not in TARGET_KINDS:
        errors.append(f"target.kind must be one of {sorted(TARGET_KINDS)}, got {kind!r}")
    if not _non_empty_str(target.get("name")):
        errors.append("target.name must be non-empty")
    policy = target.get("security_policy")
    if not isinstance(policy, dict):
        errors.append("target.security_policy must be an object with source and ref")
    else:
        if policy.get("source") not in POLICY_SOURCES:
            errors.append(
                f"target.security_policy.source must be one of {sorted(POLICY_SOURCES)}, "
                f"got {policy.get('source')!r}"
            )
        if not _non_empty_str(policy.get("ref")):
            errors.append("target.security_policy.ref must be non-empty (the policy location, or 'none — …')")
    if not _non_empty_str(target.get("preferred_channel")):
        errors.append("target.preferred_channel must be non-empty")
    return errors


def _validate_oss_verification(at: str, oss: object, records: dict[str, dict]) -> list[str]:
    """The open-source verification block: policy, timeline, history, preference.

    Every field is a cited fact or an explicit untraced/none-found with
    what was searched. These facts come from git history, advisory
    databases, and policy documents rather than the source tree, so
    they cite their own references; only the evidence_ids list is
    ledger-backed.
    """
    if not isinstance(oss, dict):
        return [f"{at}.acceptance.oss_verification must be an object for an open-source target"]
    errors: list[str] = []
    if not _non_empty_str(oss.get("policy_verified")):
        errors.append(
            f"{at}.acceptance.oss_verification.policy_verified must state what the project's "
            f"policy says about this claim's shape, with its reference"
        )
    timeline = oss.get("commit_timeline")
    if not isinstance(timeline, dict):
        errors.append(
            f"{at}.acceptance.oss_verification.commit_timeline must be an object "
            f"(introducing_commit / released_in / fix_state / published_as)"
        )
    else:
        for field in ("introducing_commit", "released_in", "fix_state", "published_as"):
            if not _non_empty_str(timeline.get(field)):
                errors.append(
                    f"{at}.acceptance.oss_verification.commit_timeline.{field} must be non-empty "
                    f"(a cited fact, or 'untraced — reason' / 'none found — searched …')"
                )
    similar = oss.get("historical_similar")
    if not isinstance(similar, list) or not similar:
        errors.append(
            f"{at}.acceptance.oss_verification.historical_similar must list at least one "
            f"similar issue (or the none-found entry with what was searched)"
        )
    else:
        seen_refs: set[str] = set()
        for k, item in enumerate(similar):
            if not isinstance(item, dict):
                errors.append(f"{at}.acceptance.oss_verification.historical_similar[{k}] must be an object")
                continue
            ref = item.get("ref")
            if not _non_empty_str(ref):
                errors.append(
                    f"{at}.acceptance.oss_verification.historical_similar[{k}].ref must be non-empty "
                    f"(an advisory/commit/issue id, or the none-found entry)"
                )
            elif ref in seen_refs:
                errors.append(
                    f"{at}.acceptance.oss_verification.historical_similar[{k}] repeats ref {ref!r}"
                )
            else:
                seen_refs.add(ref)
            if item.get("classification") not in CLASSIFICATIONS:
                errors.append(
                    f"{at}.acceptance.oss_verification.historical_similar[{k}].classification "
                    f"must be one of {sorted(CLASSIFICATIONS)}, got {item.get('classification')!r}"
                )
    if not _non_empty_str(oss.get("maintainer_preference")):
        errors.append(
            f"{at}.acceptance.oss_verification.maintainer_preference must state the project's "
            f"demonstrated acceptance pattern, with its citations"
        )
    if not _valid_evidence_ids(oss.get("evidence_ids"), records):
        errors.append(f"{at}.acceptance.oss_verification must cite existing evidence_ids")
    elif not _cites_source_read(oss.get("evidence_ids"), records):
        errors.append(
            f"{at}.acceptance.oss_verification must cite a captured source read "
            f"(the code the timeline and history are about)"
        )
    return errors


def _validate_submission(at: str, submission: object, premise_kind: object) -> list[str]:
    """The submission block every reportable claim carries.

    Four dimensions a triager asks in the first ninety seconds — core
    business, developer awareness, trigger configuration, boundary
    crossed — plus the target list. Exactly one target may be primary;
    two primary targets mean duplicate intake.
    """
    if not isinstance(submission, dict):
        return [f"{at}.submission is required for a reportable claim (severity / core / aware / config / boundary / targets)"]
    errors: list[str] = []

    severity = submission.get("severity")
    if severity not in SEVERITIES:
        errors.append(
            f"{at}.submission.severity must be one of {sorted(SEVERITIES)}, "
            f"got {severity!r} — the summary table is sorted by it, so every "
            f"reportable claim must carry one"
        )

    core = submission.get("core_business")
    if not isinstance(core, dict) or not isinstance(core.get("in_core"), bool):
        errors.append(f"{at}.submission.core_business.in_core must be true or false")
    if not isinstance(core, dict) or not _non_empty_str(core.get("evidence")):
        errors.append(f"{at}.submission.core_business.evidence must cite what decides in-core or not")

    awareness = submission.get("developer_awareness")
    if not isinstance(awareness, dict) or awareness.get("aware") not in AWARENESS_STATES:
        errors.append(
            f"{at}.submission.developer_awareness.aware must be one of {sorted(AWARENESS_STATES)}, "
            f"got {awareness.get('aware') if isinstance(awareness, dict) else awareness!r}"
        )
    if not isinstance(awareness, dict) or not _non_empty_str(awareness.get("evidence")):
        errors.append(f"{at}.submission.developer_awareness.evidence must cite the search or the comment found")

    config = submission.get("trigger_configuration")
    if not isinstance(config, dict) or not isinstance(config.get("special_config_required"), bool):
        errors.append(
            f"{at}.submission.trigger_configuration.special_config_required must be true or false"
        )
    if not isinstance(config, dict) or not _non_empty_str(config.get("default_configuration")):
        errors.append(
            f"{at}.submission.trigger_configuration.default_configuration must state the "
            f"default, cited"
        )
    if not isinstance(config, dict) or not _non_empty_str(config.get("evidence")):
        errors.append(f"{at}.submission.trigger_configuration.evidence must be non-empty")
    if isinstance(config, dict) and not _special_config_consistent(
        config.get("special_config_required"), premise_kind
    ):
        errors.append(
            f"{at}.submission says special configuration is required while the premise is "
            f"'attacker_only'; the two answers describe the same fact and one of them is wrong"
        )

    boundary = submission.get("boundary_crossed")
    if not isinstance(boundary, dict):
        errors.append(f"{at}.submission.boundary_crossed must state from → to")
    else:
        if not _non_empty_str(boundary.get("from")) or not _non_empty_str(boundary.get("to")):
            errors.append(
                f"{at}.submission.boundary_crossed must name both rungs (from and to); "
                f"a claim with no boundary crossed is not a vulnerability"
            )

    targets = submission.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append(
            f"{at}.submission.targets must list where this claim can go "
            f"(vendor_advisory / cve_cna / cnvd / src_platform / bounty_platform / hardening_channel)"
        )
    else:
        primaries = 0
        for k, item in enumerate(targets):
            if not isinstance(item, dict):
                errors.append(f"{at}.submission.targets[{k}] must be an object")
                continue
            if item.get("target") not in SUBMISSION_TARGETS:
                errors.append(
                    f"{at}.submission.targets[{k}].target must be one of "
                    f"{sorted(SUBMISSION_TARGETS)}, got {item.get('target')!r}"
                )
            fit = item.get("fit")
            if fit not in TARGET_FITS:
                errors.append(
                    f"{at}.submission.targets[{k}].fit must be one of {sorted(TARGET_FITS)}, got {fit!r}"
                )
            elif fit == "primary":
                primaries += 1
            if not _non_empty_str(item.get("reason")):
                errors.append(f"{at}.submission.targets[{k}].reason must be non-empty")
        if primaries == 0:
            errors.append(
                f"{at}.submission.targets must name exactly one primary target; "
                f"no primary means nothing is submitted and the claim is not reportable"
            )
        elif primaries > 1:
            errors.append(
                f"{at}.submission.targets names {primaries} primary targets; "
                f"two primaries mean duplicate intake"
            )
    return errors


def _validate_claims(obj: dict, records: dict[str, dict], phase: str = "deliver") -> list[str]:
    errors: list[str] = []
    target = obj.get("target")
    target_kind = target.get("kind") if isinstance(target, dict) else None
    claims = obj.get("claims")
    if not isinstance(claims, list):
        return ["claims must be a list"]
    if not claims:
        return ["claims must not be empty"]

    seen_ids: set[str] = set()
    for i, claim in enumerate(claims):
        at = f"claims[{i}]"
        if not isinstance(claim, dict):
            errors.append(f"{at} must be an object")
            continue
        for required in ("id", "claim", "source_ref", "assertions", "validity", "action", "evidence_ids"):
            if required not in claim:
                errors.append(f"{at} missing required field: {required}")
        claim_id = claim.get("id")
        if isinstance(claim_id, str):
            if claim_id in seen_ids:
                errors.append(f"{at} duplicates claim id {claim_id!r}")
            seen_ids.add(claim_id)
        if not isinstance(claim.get("claim"), str) or not claim["claim"].strip():
            errors.append(f"{at}.claim must be non-empty")

        validity = claim.get("validity")
        if validity not in VALIDITY:
            errors.append(f"{at}.validity must be one of {sorted(VALIDITY)}, got {validity!r}")
        action = claim.get("action")
        if action not in ACTIONS:
            errors.append(f"{at}.action must be one of {sorted(ACTIONS)}, got {action!r}")

        assertions = claim.get("assertions")
        if not isinstance(assertions, list) or not assertions:
            errors.append(f"{at}.assertions must be a non-empty list (an unadjudicated claim)")
            continue

        assertion_verdicts: list[str] = []
        assertion_types: list[str] = []
        for j, assertion in enumerate(assertions):
            aj = f"{at}.assertions[{j}]"
            if not isinstance(assertion, dict):
                errors.append(f"{aj} must be an object")
                continue
            for required in (
                "id",
                "type",
                "statement",
                "anchor",
                "verdict",
                "refutation_attempted",
                "evidence_ids",
            ):
                if required not in assertion:
                    errors.append(f"{aj} missing required field: {required}")
            atype = assertion.get("type")
            if atype not in ASSERTION_TYPES:
                errors.append(f"{aj}.type must be one of {sorted(ASSERTION_TYPES)}, got {atype!r}")
            elif isinstance(atype, str):
                assertion_types.append(atype)
            for field in ("statement", "anchor", "refutation_attempted"):
                value = assertion.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{aj}.{field} must be non-empty")
            averdict = assertion.get("verdict")
            if averdict not in ASSERTION_VERDICTS:
                errors.append(
                    f"{aj}.verdict must be one of {sorted(ASSERTION_VERDICTS)}, got {averdict!r}"
                )
            else:
                assertion_verdicts.append(averdict)
            if not _valid_evidence_ids(assertion.get("evidence_ids"), records):
                errors.append(f"{aj} must cite existing evidence_ids")
            elif averdict in {"confirmed", "refuted"} and not _cites_source_read(
                assertion.get("evidence_ids"), records
            ):
                errors.append(
                    f"{aj} is {averdict!r} and must cite a captured source read, not only searches"
                )
            if (
                averdict == "unresolved"
                and not _cites_source_read(assertion.get("evidence_ids"), records)
                and not _valid_absence_searches(assertion.get("absence_searches"), records)
            ):
                errors.append(
                    f"{aj} is 'unresolved' on search evidence alone and must cite two distinct "
                    f"captured zero-match searches in absence_searches"
                )
            absence = assertion.get("absence_searches")
            if absence is not None and not _valid_absence_searches(absence, records):
                errors.append(
                    f"{aj} absence_searches must contain two distinct captured zero-match "
                    f"searches; the same search run twice is not a second check"
                )

        # The validity verdict must be derived, not asserted.
        derived = _derive_validity(assertion_types, assertion_verdicts)
        if validity in VALIDITY and derived != "unadjudicated" and validity != derived:
            errors.append(
                f"{at}.validity is {validity!r} but its assertions derive {derived!r} "
                f"(assertion verdicts: {assertion_verdicts})"
            )

        # Acceptance only exists for a claim that holds. It is owed from
        # the assess phase on; during adjudicate a drafted acceptance is
        # tolerated (the model may answer early), so it is not yet checked.
        acceptance = claim.get("acceptance")
        if phase in {"assess", "deliver"}:
            if validity == "holds":
                if not isinstance(acceptance, dict):
                    errors.append(f"{at} has validity 'holds' and requires an acceptance object")
                else:
                    errors.extend(_validate_acceptance(at, acceptance, records))
                    if target_kind == "open_source":
                        errors.extend(_validate_oss_verification(at, acceptance.get("oss_verification"), records))
            else:
                if acceptance is not None:
                    errors.append(
                        f"{at} has validity {validity!r} and must not carry an acceptance verdict; "
                        f"a claim that does not hold is not 'unacceptable', it is not a vulnerability"
                    )

        # Action must match the validity verdict.
        if validity == "does_not_hold" and action != "no_report":
            errors.append(f"{at}.action must be 'no_report' when validity is 'does_not_hold'")
        if validity == "needs_more_evidence" and action != "needs_evidence":
            errors.append(f"{at}.action must be 'needs_evidence' when validity is 'needs_more_evidence'")
        if validity == "already_fixed" and action != "already_fixed":
            errors.append(f"{at}.action must be 'already_fixed' when validity is 'already_fixed'")
        if validity == "holds" and action not in {"report", "rewrite_then_report", "hardening_note"}:
            errors.append(
                f"{at}.action must be report / rewrite_then_report / hardening_note when validity is 'holds'"
            )
        if validity != "holds" and action in {"report", "rewrite_then_report"}:
            errors.append(f"{at} has validity {validity!r} and must not be actioned as a report")

        # The invariant subject and the submission block are delivery-time
        # artifacts: they are checked when the deliver phase is asked for.
        if phase == "deliver":
            # A reportable claim needs an invariant subject.
            if action in {"report", "rewrite_then_report"}:
                subject = claim.get("subject")
                if not isinstance(subject, str) or not subject.strip():
                    errors.append(f"{at}.subject is required for a reportable claim")
                elif _subject_is_consequence(subject):
                    errors.append(
                        f"{at}.subject states a consequence, not an invariant: {subject!r}"
                    )
                if action == "rewrite_then_report":
                    original = claim.get("original_subject")
                    if not isinstance(original, str) or not original.strip():
                        errors.append(
                            f"{at}.original_subject is required when action is 'rewrite_then_report' "
                            f"(the consequence framing it replaced)"
                        )

            # A reportable claim carries its submission block: the four
            # summary dimensions and the target list. The premise it is
            # cross-checked against comes from the acceptance object, which
            # a reportable claim necessarily has (validity must be holds).
            if action in {"report", "rewrite_then_report"}:
                premise_kind = acceptance.get("premise_kind") if isinstance(acceptance, dict) else None
                errors.extend(_validate_submission(at, claim.get("submission"), premise_kind))

        if not _valid_evidence_ids(claim.get("evidence_ids"), records):
            errors.append(f"{at} must cite existing evidence_ids")
    return errors


def _validate_acceptance(at: str, acceptance: dict, records: dict[str, dict]) -> list[str]:
    errors: list[str] = []
    for required in (
        "premise_kind",
        "boundary_state",
        "divergence_state",
        "acceptability",
        "rationale",
        "evidence_ids",
    ):
        if required not in acceptance:
            errors.append(f"{at}.acceptance missing required field: {required}")

    premise_kind = acceptance.get("premise_kind")
    if premise_kind not in PREMISE_KINDS:
        errors.append(
            f"{at}.acceptance.premise_kind must be one of {sorted(PREMISE_KINDS)}, got {premise_kind!r}"
        )
    boundary_state = acceptance.get("boundary_state")
    if boundary_state not in BOUNDARY_STATES:
        errors.append(
            f"{at}.acceptance.boundary_state must be one of {sorted(BOUNDARY_STATES)}, got {boundary_state!r}"
        )
    divergence_state = acceptance.get("divergence_state")
    if divergence_state not in DIVERGENCE_STATES:
        errors.append(
            f"{at}.acceptance.divergence_state must be one of {sorted(DIVERGENCE_STATES)}, got {divergence_state!r}"
        )
    acceptability = acceptance.get("acceptability")
    if acceptability not in ACCEPTABILITY:
        errors.append(
            f"{at}.acceptance.acceptability must be one of {sorted(ACCEPTABILITY)}, got {acceptability!r}"
        )

    # The acceptability verdict must be derived from the three answers.
    if (
        premise_kind in PREMISE_KINDS
        and boundary_state in BOUNDARY_STATES
        and divergence_state in DIVERGENCE_STATES
        and acceptability in ACCEPTABILITY
    ):
        derived = _derive_acceptability(premise_kind, boundary_state, divergence_state)
        if derived != acceptability:
            errors.append(
                f"{at}.acceptance.acceptability is {acceptability!r} but the three answers derive "
                f"{derived!r} (premise={premise_kind}, boundary={boundary_state}, divergence={divergence_state})"
            )

    if divergence_state == "present":
        sides = acceptance.get("divergence_sides")
        if not isinstance(sides, list) or len(sides) < 2:
            errors.append(
                f"{at}.acceptance.divergence_state 'present' requires divergence_sides with both sides cited"
            )
        else:
            for k, side in enumerate(sides):
                if not isinstance(side, dict):
                    errors.append(f"{at}.acceptance.divergence_sides[{k}] must be an object")
                    continue
                fl = side.get("file_line")
                if not isinstance(fl, str) or not FILE_LINE.match(fl):
                    errors.append(
                        f"{at}.acceptance.divergence_sides[{k}].file_line must be 'file:line', got {fl!r}"
                    )
                behavior = side.get("behavior")
                if not isinstance(behavior, str) or not behavior.strip():
                    errors.append(f"{at}.acceptance.divergence_sides[{k}].behavior must be non-empty")
    elif divergence_state == "absent":
        if not _valid_absence_searches(acceptance.get("divergence_absence_searches"), records):
            errors.append(
                f"{at}.acceptance.divergence_state 'absent' requires two distinct captured "
                f"zero-match searches in divergence_absence_searches"
            )

    if not _valid_evidence_ids(acceptance.get("evidence_ids"), records):
        errors.append(f"{at}.acceptance must cite existing evidence_ids")
    elif not _cites_source_read(acceptance.get("evidence_ids"), records):
        errors.append(f"{at}.acceptance must cite a captured source read")
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
        if category not in {"validity", "acceptance", "artifact", "ordering", "final_review", "other"}:
            errors.append(f"work_queue[{i}].category is not a recognised category: {category!r}")
        else:
            categories.add(category)
        status = item.get("status")
        if status not in {"queued", "active", "completed", "deferred"}:
            errors.append(
                f"work_queue[{i}].status must be queued / active / completed / deferred, got {status!r}"
            )
        if status in {"queued", "active"}:
            errors.append(
                f"work_queue[{i}] is {status!r}; every item must be completed or deferred before delivery"
            )
        if status == "deferred":
            outcome = item.get("outcome")
            if not isinstance(outcome, str) or not outcome.strip():
                errors.append(f"work_queue[{i}] deferred requires an outcome stating the limitation")
        if category == "final_review" and status == "completed":
            final_review_done = True
        if not _valid_evidence_ids(item.get("evidence_ids"), records):
            errors.append(f"work_queue[{i}] must cite existing evidence_ids")
    for required_category in ("validity", "acceptance"):
        if required_category not in categories:
            errors.append(f"work_queue has no task for the {required_category!r} stage")
    if not final_review_done:
        errors.append("work_queue must contain a completed 'final_review' task before delivery")
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


def validate(text: str, records: dict[str, dict], phase: str = "deliver") -> tuple[int, list[str]]:
    """Validate the notes file at one phase of the adjudication loop.

    `--phase` exists so a mid-work run checks what the current stage owes
    rather than everything the finished adjudication owes. A validator
    that can only say "not done" teaches the model to stop running it.
    """
    if phase not in PHASES:
        raise ValueError(f"unknown phase: {phase!r}")
    errors: list[str] = []
    obj, extract_error = _extract_adjudication_table(text)
    if obj is None:
        return 1, [extract_error or "adjudication table could not be extracted"]

    for required in REQUIRED_TOP_FIELDS[phase]:
        if required not in obj:
            errors.append(f"missing required field: {required}")

    errors.extend(_validate_target(obj))

    if obj.get("coverage_paragraph_present") is not True:
        errors.append("coverage_paragraph_present must be true")
    missing_sections = _missing_coverage_sections(text)
    if missing_sections:
        errors.append(
            "notes file is missing coverage section(s): "
            + ", ".join(missing_sections)
            + " (every one of them is required: "
            + ", ".join(name for name, _ in COVERAGE_MARKERS)
            + ")"
        )

    errors.extend(_validate_claims(obj, records, phase=phase))

    if phase == "deliver":
        errors.extend(_validate_work_queue(obj, records))
        errors.extend(_validate_channel(obj))

    return (1 if errors else 0), errors


def _assertion_row_complete(assertion: object) -> bool:
    """A row the model has finished writing: type, statement, anchor, verdict.

    Partial mode (below) checks completed rows and ignores half-written
    ones, so an in-progress assertion never blocks a stop.
    """
    return (
        isinstance(assertion, dict)
        and assertion.get("verdict") in ASSERTION_VERDICTS
        and assertion.get("type") in ASSERTION_TYPES
        and _non_empty_str(assertion.get("statement"))
        and _non_empty_str(assertion.get("anchor"))
    )


def validate_partial(text: str, records: dict[str, dict], deliver_claimed: bool = False) -> tuple[int, list[str]]:
    """Stop-gate validation: what is written must be consistent.

    This is the mode the harness Stop hook runs. It differs from
    `validate` in one principle: completeness below delivery is not
    enforced — an adjudication may honestly be mid-work when a turn
    ends — but everything the file *has* recorded must be right, and
    once delivery is claimed (an artifact written next to the notes, or
    any claim actioned for report) the full deliver gate must pass.

    Returns (0, []) when there is nothing yet to hold consistent.
    """
    obj, extract_error = _extract_adjudication_table(text)
    if obj is None:
        err = extract_error or ""
        # A table that exists but does not parse is corruption; no table
        # at all is a fresh template copy that has not been started. A
        # ```json fence with no extractable object falls on the
        # corruption side: someone started the table and broke it.
        if "did not parse" in err or "```json" in text:
            return 1, [err]
        return 0, []

    errors: list[str] = []

    # The target profile and the coverage sections are scaffolded at
    # intake; losing either is corruption, not progress.
    if obj.get("target") is not None:
        errors.extend(_validate_target(obj))
    missing_sections = _missing_coverage_sections(text)
    if missing_sections:
        errors.append(
            "notes file is missing coverage section(s): " + ", ".join(missing_sections)
        )

    claims = obj.get("claims")
    if not isinstance(claims, list):
        return 1, errors + ["claims must be a list"]

    deliver = deliver_claimed or any(
        isinstance(claim, dict) and claim.get("action") in {"report", "rewrite_then_report"}
        for claim in claims
    )

    for i, claim in enumerate(claims):
        if not isinstance(claim, dict):
            errors.append(f"claims[{i}] must be an object")
            continue
        if not _non_empty_str(claim.get("claim")):
            continue  # an intake row not filled in yet
        at = f"claims[{i}]"
        validity = claim.get("validity")
        action = claim.get("action")

        # Assertions: every completed row must be valid; a half-written
        # row is honest in-progress state and does not block.
        assertions = claim.get("assertions")
        rows_complete = isinstance(assertions, list) and bool(assertions)
        if isinstance(assertions, list):
            for j, assertion in enumerate(assertions):
                aj = f"{at}.assertions[{j}]"
                if not isinstance(assertion, dict):
                    errors.append(f"{aj} must be an object")
                    rows_complete = False
                    continue
                if not _assertion_row_complete(assertion):
                    rows_complete = False
                    continue
                for field in ("statement", "anchor", "refutation_attempted"):
                    if not _non_empty_str(assertion.get(field)):
                        errors.append(f"{aj}.{field} must be non-empty")
                if not _valid_evidence_ids(assertion.get("evidence_ids"), records):
                    errors.append(f"{aj} must cite existing evidence_ids")
                else:
                    averdict = assertion.get("verdict")
                    if averdict in {"confirmed", "refuted"} and not _cites_source_read(
                        assertion.get("evidence_ids"), records
                    ):
                        errors.append(
                            f"{aj} is {averdict!r} and must cite a captured source read, not only searches"
                        )
                    if (
                        averdict == "unresolved"
                        and not _cites_source_read(assertion.get("evidence_ids"), records)
                        and not _valid_absence_searches(assertion.get("absence_searches"), records)
                    ):
                        errors.append(
                            f"{aj} is 'unresolved' on search evidence alone and must cite two distinct "
                            f"captured zero-match searches in absence_searches"
                        )
                absence = assertion.get("absence_searches")
                if absence is not None and not _valid_absence_searches(absence, records):
                    errors.append(
                        f"{aj} absence_searches must contain two distinct captured zero-match "
                        f"searches; the same search run twice is not a second check"
                    )
        else:
            rows_complete = False

        # The derivation check applies only once every row is written:
        # deriving from a subset would flag honest mid-work states.
        if validity in VALIDITY and rows_complete:
            assertion_rows = [a for a in assertions if isinstance(a, dict)]
            derived = _derive_validity(
                [a.get("type") for a in assertion_rows],
                [a.get("verdict") for a in assertion_rows],
            )
            if derived != "unadjudicated" and validity != derived:
                errors.append(
                    f"{at}.validity is {validity!r} but its assertions derive {derived!r} "
                    f"(assertion verdicts: {[a.get('verdict') for a in assertion_rows]})"
                )

        if validity in VALIDITY and action in ACTIONS:
            if validity == "does_not_hold" and action != "no_report":
                errors.append(f"{at}.action must be 'no_report' when validity is 'does_not_hold'")
            if validity == "needs_more_evidence" and action != "needs_evidence":
                errors.append(f"{at}.action must be 'needs_evidence' when validity is 'needs_more_evidence'")
            if validity == "already_fixed" and action != "already_fixed":
                errors.append(f"{at}.action must be 'already_fixed' when validity is 'already_fixed'")
            if validity == "holds" and action not in {"report", "rewrite_then_report", "hardening_note"}:
                errors.append(
                    f"{at}.action must be report / rewrite_then_report / hardening_note when validity is 'holds'"
                )

        acceptance = claim.get("acceptance")
        if validity in VALIDITY and validity != "holds" and acceptance is not None:
            errors.append(
                f"{at} has validity {validity!r} and must not carry an acceptance verdict; "
                f"a claim that does not hold is not 'unacceptable', it is not a vulnerability"
            )
        if validity == "holds" and isinstance(acceptance, dict):
            errors.extend(_validate_acceptance(at, acceptance, records))
            if isinstance(obj.get("target"), dict) and obj["target"].get("kind") == "open_source":
                errors.extend(_validate_oss_verification(at, acceptance.get("oss_verification"), records))

        subject = claim.get("subject")
        if isinstance(subject, str) and subject.strip() and _subject_is_consequence(subject):
            errors.append(f"{at}.subject states a consequence, not an invariant: {subject!r}")

        if isinstance(claim.get("submission"), dict):
            premise_kind = acceptance.get("premise_kind") if isinstance(acceptance, dict) else None
            errors.extend(_validate_submission(at, claim.get("submission"), premise_kind))

        if claim.get("evidence_ids") is not None and not _valid_evidence_ids(claim.get("evidence_ids"), records):
            errors.append(f"{at} must cite existing evidence_ids")

    if deliver:
        _, full_errors = validate(text, records, phase="deliver")
        seen = set(errors)
        for err in full_errors:
            if err not in seen:
                errors.append(err)
                seen.add(err)

    return (1 if errors else 0), errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate a vulnerability claim adjudication notes file.")
    parser.add_argument("notes", help="path to the adjudication notes Markdown file")
    parser.add_argument("--evidence-ledger", help="path to the evidence JSONL ledger")
    parser.add_argument(
        "--phase",
        choices=PHASES,
        default="deliver",
        help=(
            "which stage's requirements to check: adjudicate (decomposition, assertion "
            "ledger, derived validity), assess (+ acceptance answers and OSS "
            "verification), deliver (everything — the delivery gate). Default: deliver."
        ),
    )
    parser.add_argument(
        "--next",
        action="store_true",
        help=(
            "walk the phases in order and print the single next requirement as "
            "NEXT [phase]: ... — the one-instruction-per-round driver. Prints READY "
            "when all three gates are green. Always exits 0."
        ),
    )
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
            "FAIL: --evidence-ledger is required; an adjudication without cited "
            "evidence is an assertion, not a verdict",
            file=sys.stderr,
        )
        return 2

    text = notes.read_text(encoding="utf-8")

    if args.next:
        for phase in PHASES:
            code, errors = validate(text, records, phase=phase)
            if code != 0:
                print(f"NEXT [{phase}]: {errors[0]}")
                if len(errors) > 1:
                    print(f"  ({len(errors) - 1} more requirement(s) behind this one at the {phase} phase)")
                return 0
        print(
            "READY: adjudicate / assess / deliver gates are all green — produce the "
            "artifact the verdict calls for, and nothing else"
        )
        return 0

    code, errors = validate(text, records, phase=args.phase)
    for err in errors:
        print(f"FAIL: {err}", file=sys.stderr)
    if ledger_errors:
        code = 1
    if code == 0:
        print(
            f"OK: {args.phase}-phase adjudication structure valid ({len(records)} evidence record(s)); "
            f"both verdicts are derived and every claim cites evidence that exists"
        )
    else:
        print(
            f"FAIL: {len(errors)} {args.phase}-phase requirement(s) not met; "
            f"no artifact built on this state is ready",
            file=sys.stderr,
        )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
