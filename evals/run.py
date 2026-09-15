#!/usr/bin/env python3
"""Eval regression suite (Hardening v1.1 §12).

v1 shipped 30 fixtures and no runner, so nothing kept the corpus honest and
nothing stopped a runtime/prompt change from quietly making the audit worse.
This harness turns the corpus into a gate.

Modes
-----

``--oracle``
    Predict each fixture's *own* expected values. Metrics must be perfect.
    Used to verify (a) the corpus is internally consistent and (b) the harness
    math is right. This is the mode CI runs as a structural regression check.

``--predictions PATH``
    Score a prediction file produced by an actual audit run
    (``{fixture_id: {"verdict": ..., "disposition_reason": ..., "severity": ...}}``,
    or a list of ``{"id": ...}`` records). This is the mode that measures real
    audit quality.

*(default)*
    A deterministic keyword/state baseline (:func:`baseline_predict`) that
    stands in for an LLM so CI can run without model access. It applies the
    permission-delta style screens the fixtures are built around. It is a
    **corpus harness, not an auditor** — its job is to make the metric
    thresholds enforceable and to fail loudly when the corpus or the screening
    rules drift.

``--self-check``
    Validate corpus structure: unique ids, expected-vs-actual totals in
    ``expected.json``, disposition labels that exist in (or alias into) the
    finding schema.

Exit codes: 0 pass, 1 threshold violation, 2 corpus/usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

HERE = Path(__file__).resolve().parent
SKILL_ROOT = HERE.parent
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from evals.score import (  # noqa: E402
    CANONICAL_DISPOSITIONS,
    CONFIRMED,
    DISPOSITION_ALIASES,
    NEEDS_VALIDATION,
    REJECTED,
    Metrics,
    check_thresholds,
    format_report,
    hard_bug_classes,
    score,
    thresholds_from_expected,
)

FIXTURE_DIRS = ("positive", "negative", "ambiguous")

# ---------------------------------------------------------------------------
# Baseline predictor
# ---------------------------------------------------------------------------

# Ordered screens. First match wins, so dismissal must precede ambiguity and
# ambiguity must precede confirmation (see module docstring).
DISMISSALS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("duplicate", ("same bug", "already in findings.json", "duplicate of", "same trace, same root cause"), "duplicate"),
    ("scanner_fp", ("scanner false positive", "parameterized sql", "no string interpolation",
                    "prepared statement"), "hypothetical_chain"),
    ("already_fixed", ("fix landed in", "fixed in v", "verified absent", "no longer present",
                       "code path verified absent"), "fix_as_proof"),
    ("unreachable", ("no way to reach", "not by any http handler", "not reachable",
                     "unreachable from"), "keyword_cvss"),
    ("post_compromise", ("not a privilege escalation", "requires admin —", "requires admin -",
                         "post-compromise", "already has admin credentials"), "post_compromise"),
    ("deployment_override", ("deployment override", "overrides via", "override via",
                             "overridden", "meant for dev", "dev only", "development only",
                             "documented as such"), "admin_action_required"),
    ("not_a_requirement", ("does not require unauthenticated", "acceptable behavior for malformed",
                           "no security requirement", "not a security requirement"), "invented_permission"),
    ("out_of_scope", ("not exploitable in this project", "defer to upstream", "upstream tracking",
                      "out of scope"), "out_of_scope"),
    ("intended", ("intentionally public", "by design", "as a feature", "legacy_security_default",
                  "spec_compliant_weak_default", "matches the framework default",
                  "framework security policy", "intentional, documented"), "hardening_only"),
    ("disabled_in_production", ("set to false in production", "is set to false",
                                "disabled in production", "verified at deploy time"), "hardening_only"),
    ("equivalent_capability", ("already has ", "already have ", "product docs explicitly list",
                               "documented feature"), "equivalent_capability"),
    ("browser_mitigates", ("modern browsers", "browser mitigates", "no ie11 users"), "speculative_client_behavior"),
    ("alleged_without_repro", ("allegedly",), "hypothetical_chain"),
    ("spec_only", ("should be", "best practice", "owasp recommends"), "hardening_only"),
)

AMBIGUITY_MARKERS = (
    "cannot tell", "we cannot", "don't know", "do not know", "not yet inspected",
    "need to verify", "needs verification", "depends on whether", "depends on the specific",
    "without running a real", "requires sandbox", "requires reproduction",
    "unverified", "unknown whether", "may be exploitable", "may allow", "may permit",
    "not been triggered", "no telemetry", "we don't know", "not inspected",
)

CONFIRMATION_MARKERS = (
    "does not check", "does not validate", "does not block", "does not require a csrf",
    "without validating", "without a transaction", "without a lock", "without an allowlist",
    "without allowlist", "without payment", "without ownership", "no ownership check",
    "misses the ownership", "trusts ", "string concatenation", "unescaped", "unchecked",
    "missing csrf", "csrf protection layer is missing", "accepts arbitrary",
    "attacker-controlled", "attacker controlled", "os.system", "crafted pickle",
    "no authentication", "bypasses",
)

CLASS_SEVERITY: dict[str, str] = {
    "rce": "critical",
    "code_injection": "critical",
    "deserialization": "critical",
    "sql_injection": "critical",
    "broken_authentication": "critical",
    "open_redirect": "critical",
    "ssrf": "high",
    "idor": "high",
    "csrf": "high",
    "race_condition": "high",
    "business_logic": "high",
    "state_machine": "high",
    "path_traversal": "high",
    "authorization": "high",
}


def _haystack(fixture: Mapping[str, Any]) -> str:
    """Lowercased blob of the fixture's input fields the screens look at."""
    inp = fixture.get("input") or {}
    parts = [
        str(fixture.get("name", "")),
        str(fixture.get("class", "")),
        str(inp.get("title", "")),
        str(inp.get("summary", "")),
        str(inp.get("root_cause", "")),
    ]
    for key in ("default_security", "execution", "boundary", "evidence"):
        value = inp.get(key)
        if value:
            parts.append(json.dumps(value, ensure_ascii=False))
    for step in inp.get("trace") or []:
        if isinstance(step, Mapping):
            parts.append(json.dumps(step, ensure_ascii=False))
    return " ".join(parts).lower()


def baseline_predict(fixture: Mapping[str, Any]) -> dict[str, Any]:
    """Deterministic stand-in predictor (see module docstring)."""
    blob = _haystack(fixture)
    fixture_class = str(fixture.get("class", "")).lower()

    for _name, markers, reason in DISMISSALS:
        if any(m in blob for m in markers):
            return {"verdict": REJECTED, "disposition_reason": reason, "severity": None}

    if any(m in blob for m in AMBIGUITY_MARKERS):
        return {"verdict": NEEDS_VALIDATION, "disposition_reason": None, "severity": None}

    if any(m in blob for m in CONFIRMATION_MARKERS):
        return {
            "verdict": CONFIRMED,
            "disposition_reason": None,
            "severity": CLASS_SEVERITY.get(fixture_class, "high"),
        }

    return {"verdict": NEEDS_VALIDATION, "disposition_reason": None, "severity": None}


# ---------------------------------------------------------------------------
# Corpus loading / validation
# ---------------------------------------------------------------------------


def load_fixtures(evals_dir: Path = HERE) -> list[dict[str, Any]]:
    fixtures: list[dict[str, Any]] = []
    for sub in FIXTURE_DIRS:
        for path in sorted((evals_dir / sub).glob("*.json")):
            with open(path, "r", encoding="utf-8") as f:
                payload = json.load(f)
            payload.setdefault("_path", str(path.relative_to(evals_dir)))
            payload.setdefault("_bucket", sub)
            fixtures.append(payload)
    return fixtures


def load_expected(evals_dir: Path = HERE) -> dict[str, Any]:
    path = evals_dir / "expected.json"
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_predictions(path: Path) -> dict[str, Mapping[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        payload = json.load(f)
    if isinstance(payload, Mapping):
        return {str(k): v for k, v in payload.items()}
    if isinstance(payload, list):
        out: dict[str, Mapping[str, Any]] = {}
        for item in payload:
            if isinstance(item, Mapping) and item.get("id"):
                out[str(item["id"])] = item
        return out
    raise ValueError(f"unsupported predictions format in {path}")


def oracle_predictions(fixtures: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {
        str(f["id"]): {
            "verdict": f.get("expected_verdict"),
            "disposition_reason": f.get("expected_disposition_reason"),
            "severity": f.get("expected_min_severity"),
        }
        for f in fixtures
    }


def self_check(fixtures: Sequence[Mapping[str, Any]], expected: Mapping[str, Any]) -> list[str]:
    """Return corpus-consistency errors (empty == consistent)."""
    errors: list[str] = []

    ids = [str(f.get("id", "")) for f in fixtures]
    if len(set(ids)) != len(ids):
        seen: set[str] = set()
        dupes = sorted({i for i in ids if i in seen or seen.add(i)})
        errors.append(f"duplicate fixture ids: {dupes}")

    for f in fixtures:
        fid = f.get("id", "<no id>")
        verdict = f.get("expected_verdict")
        if verdict not in (CONFIRMED, REJECTED, NEEDS_VALIDATION):
            errors.append(f"{fid}: invalid expected_verdict {verdict!r}")
        reason = f.get("expected_disposition_reason")
        if reason is not None and reason not in CANONICAL_DISPOSITIONS and reason not in DISPOSITION_ALIASES:
            errors.append(f"{fid}: disposition_reason {reason!r} is neither canonical nor a known alias")
        if not f.get("input") or not isinstance(f["input"], Mapping):
            errors.append(f"{fid}: missing/invalid 'input'")
        if not f.get("rationale"):
            errors.append(f"{fid}: missing 'rationale'")

    totals = expected.get("totals") or {}
    for bucket in FIXTURE_DIRS:
        actual = sum(1 for f in fixtures if f.get("_bucket") == bucket)
        claimed = totals.get(bucket)
        if claimed is not None and claimed != actual:
            errors.append(f"expected.json totals.{bucket}={claimed} but {actual} fixtures on disk")
    if totals.get("total") is not None and totals["total"] != len(fixtures):
        errors.append(f"expected.json totals.total={totals['total']} but {len(fixtures)} fixtures on disk")

    vd = expected.get("verdict_distribution") or {}
    for verdict in (CONFIRMED, REJECTED, NEEDS_VALIDATION):
        if verdict in vd:
            actual = sum(1 for f in fixtures if f.get("expected_verdict") == verdict)
            if vd[verdict] != actual:
                errors.append(f"expected.json verdict_distribution.{verdict}={vd[verdict]} but {actual} fixtures")

    # Fixtures listed in expected.json must exist and vice versa.
    listed = {str(p) for p in (expected.get("fixtures") or [])}
    on_disk = {str(f.get("_path")) for f in fixtures}
    for missing in sorted(listed - on_disk):
        errors.append(f"expected.json lists {missing} but it is not on disk")
    for extra in sorted(on_disk - listed):
        errors.append(f"{extra} exists but is not listed in expected.json")

    return errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="evals/run.py",
                                description="mini-audit eval regression suite")
    p.add_argument("--evals-dir", default=str(HERE))
    p.add_argument("--predictions", default=None,
                   help="prediction JSON to score (audit output)")
    p.add_argument("--oracle", action="store_true",
                   help="predict each fixture's own expectation (harness self-test)")
    p.add_argument("--self-check", action="store_true",
                   help="validate corpus structure and exit")
    p.add_argument("--json", action="store_true", help="emit machine-readable metrics")
    p.add_argument("--write-floor", default=None,
                   help="write the achieved metrics to this path as a CI floor")
    p.add_argument("--min-precision", type=float, default=None)
    p.add_argument("--min-recall", type=float, default=None)
    p.add_argument("--min-f1", type=float, default=None)
    p.add_argument("--min-hard-bug-recall", type=float, default=None)
    p.add_argument("--min-disposition-accuracy", type=float, default=None)
    p.add_argument("--max-fp-rate", type=float, default=None)
    p.add_argument("--max-needs-validation-rate", type=float, default=None)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    evals_dir = Path(args.evals_dir).resolve()

    fixtures = load_fixtures(evals_dir)
    expected = load_expected(evals_dir)
    if not fixtures:
        print(f"no eval fixtures found under {evals_dir}", file=sys.stderr)
        return 2

    corpus_errors = self_check(fixtures, expected)
    if args.self_check:
        report = {
            "fixtures": len(fixtures),
            "errors": corpus_errors,
            "ok": not corpus_errors,
        }
        print(json.dumps(report, indent=2) if args.json else
              (f"corpus self-check: {len(fixtures)} fixtures, {len(corpus_errors)} error(s)"
               + ("".join(f"\n  - {e}" for e in corpus_errors) if corpus_errors else "")))
        return 0 if not corpus_errors else 2

    if corpus_errors:
        print("corpus self-check failed:", file=sys.stderr)
        for e in corpus_errors:
            print(f"  - {e}", file=sys.stderr)
        return 2

    if args.oracle:
        predictions = oracle_predictions(fixtures)
        mode = "oracle"
    elif args.predictions:
        try:
            predictions = load_predictions(Path(args.predictions))
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            print(f"cannot read predictions: {exc}", file=sys.stderr)
            return 2
        mode = "predictions"
    else:
        predictions = {str(f["id"]): baseline_predict(f) for f in fixtures}
        mode = "baseline"

    metrics: Metrics = score(fixtures, predictions, hard_bug_classes=hard_bug_classes(expected))

    thresholds = thresholds_from_expected(expected)
    overrides = {
        "min_precision": args.min_precision,
        "min_recall": args.min_recall,
        "min_f1": args.min_f1,
        "min_hard_bug_recall": args.min_hard_bug_recall,
        "min_disposition_accuracy": args.min_disposition_accuracy,
        "max_false_positive_rate": args.max_fp_rate,
        "max_needs_validation_rate": args.max_needs_validation_rate,
    }
    for key, value in overrides.items():
        if value is not None:
            thresholds[key] = value

    violations = check_thresholds(metrics, thresholds)

    if args.write_floor:
        floor = {
            "schema_version": 1,
            "generated_by": "evals/run.py",
            "mode": mode,
            "thresholds": thresholds,
            "achieved": metrics.to_dict(),
        }
        Path(args.write_floor).write_text(json.dumps(floor, indent=2) + "\n", encoding="utf-8")

    if args.json:
        print(json.dumps({
            "mode": mode,
            "metrics": metrics.to_dict(),
            "thresholds": thresholds,
            "violations": violations,
            "ok": not violations,
        }, indent=2))
    else:
        print(format_report(metrics, title=f"eval ({mode})"))
        print("  thresholds: " + ", ".join(
            f"{k}={v}" for k, v in sorted(thresholds.items())))
        if violations:
            print("THRESHOLD VIOLATIONS:")
            for v in violations:
                print(f"  - {v}")
        else:
            print("thresholds: PASS")

    return 0 if not violations else 1


if __name__ == "__main__":
    raise SystemExit(main())
