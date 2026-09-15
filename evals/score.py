"""Eval scoring (Hardening v1.1 §12).

Pure functions over ``(predictions, expectations)`` so the metric definitions
are unit-testable without running an audit.

Binary framing
--------------

A *positive* is "this fixture is a real vulnerability", i.e. its fixture says
``expected_verdict == "confirmed"``. A *predicted positive* is
``predicted_verdict == "confirmed"``. Everything else is a negative.

    TP  expected confirmed  & predicted confirmed
    FN  expected confirmed  & predicted not confirmed
    FP  expected not-confirmed & predicted confirmed
    TN  expected not-confirmed & predicted not confirmed

``needs_validation`` is not a positive and not a negative-with-confidence: it
is an abstention, tracked separately via ``needs_validation_rate``. Treating an
abstention as a confirmed finding is exactly the over-confirmation failure mode
the permission-delta framework exists to prevent, so it must never count as TP.
"""

from __future__ import annotations

import dataclasses
from typing import Any, Iterable, Mapping, Optional, Sequence

CONFIRMED = "confirmed"
REJECTED = "rejected"
NEEDS_VALIDATION = "needs_validation"

VERDICTS = (CONFIRMED, REJECTED, NEEDS_VALIDATION)

# Corpus labels that are not in the finding schema's disposition_reason enum.
# `admin_action_required` is the failure mode name used by the policy layer
# ("an admin must opt in"), which maps onto the schema value
# `by_design`/`equivalent_capability` depending on framing. Reported as a
# warning rather than silently accepted, so corpus/schema drift stays visible.
DISPOSITION_ALIASES: dict[str, str] = {
    "admin_action_required": "by_design",
    "admin_misconfiguration": "by_design",
    "false_positive": "insufficient_evidence",
}

# Canonical reasons, mirrored from runtime.findings.DISPOSITION_REASONS.
CANONICAL_DISPOSITIONS: frozenset[str] = frozenset({
    "by_design", "equivalent_capability", "post_compromise", "invented_permission",
    "keyword_cvss", "hypothetical_chain", "default_state_confusion",
    "speculative_client_behavior", "fix_as_proof", "insufficient_evidence",
    "hardening_only", "duplicate", "out_of_scope",
})

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclasses.dataclass
class Metrics:
    total: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    needs_validation: int = 0
    positives: int = 0
    negatives: int = 0
    # Hard-bug subset
    hard_total: int = 0
    hard_recalled: int = 0
    # Disposition fidelity on fixtures that expect a specific reason
    disposition_checked: int = 0
    disposition_correct: int = 0
    # Severity ordering on true positives
    severity_checked: int = 0
    severity_satisfied: int = 0
    missing_predictions: int = 0
    warnings: list[str] = dataclasses.field(default_factory=list)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return (self.tp / denom) if denom else 1.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return (self.tp / denom) if denom else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        """FP / (FP + TN) — share of non-vulnerabilities reported as findings."""
        denom = self.fp + self.tn
        return (self.fp / denom) if denom else 0.0

    @property
    def needs_validation_rate(self) -> float:
        return (self.needs_validation / self.total) if self.total else 0.0

    @property
    def hard_bug_recall(self) -> float:
        return (self.hard_recalled / self.hard_total) if self.hard_total else 1.0

    @property
    def disposition_accuracy(self) -> float:
        return (self.disposition_correct / self.disposition_checked) if self.disposition_checked else 1.0

    @property
    def severity_accuracy(self) -> float:
        return (self.severity_satisfied / self.severity_checked) if self.severity_checked else 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "positives": self.positives,
            "negatives": self.negatives,
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn,
            "needs_validation": self.needs_validation,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "needs_validation_rate": round(self.needs_validation_rate, 4),
            "hard_bug_recall": round(self.hard_bug_recall, 4),
            "hard_total": self.hard_total,
            "hard_recalled": self.hard_recalled,
            "disposition_accuracy": round(self.disposition_accuracy, 4),
            "severity_accuracy": round(self.severity_accuracy, 4),
            "missing_predictions": self.missing_predictions,
            "warnings": list(self.warnings),
        }


def normalize_prediction(prediction: Mapping[str, Any]) -> dict[str, Any]:
    """Accept either ``{"verdict": ...}`` or ``{"expected_verdict": ...}``
    (an "oracle" prediction) and normalize the verdict key."""
    verdict = prediction.get("verdict") or prediction.get("expected_verdict") or NEEDS_VALIDATION
    reason = prediction.get("disposition_reason")
    if reason is None:
        reason = prediction.get("expected_disposition_reason")
    severity = prediction.get("severity")
    if isinstance(severity, Mapping):
        severity = severity.get("overall")
    if severity is None:
        severity = prediction.get("expected_min_severity")
    return {"verdict": verdict, "disposition_reason": reason, "severity": severity}


def score(
    fixtures: Sequence[Mapping[str, Any]],
    predictions: Mapping[str, Mapping[str, Any]],
    *,
    hard_bug_classes: Iterable[str] = (),
    treat_missing_as_needs_validation: bool = True,
) -> Metrics:
    """Compute the metric set.

    *fixtures* are the eval fixture documents (each with ``id``,
    ``expected_verdict``, optional ``expected_disposition_reason`` and
    ``expected_min_severity``). *predictions* maps fixture id → prediction.
    """
    hard = {c.lower() for c in hard_bug_classes}
    m = Metrics()

    for fixture in fixtures:
        fid = fixture.get("id", "")
        expected_verdict = fixture.get("expected_verdict", NEEDS_VALIDATION)
        expected_reason = fixture.get("expected_disposition_reason")
        expected_min_sev = fixture.get("expected_min_severity")
        fixture_class = str(fixture.get("class", "")).lower()

        raw = predictions.get(fid)
        if raw is None:
            m.missing_predictions += 1
            if not treat_missing_as_needs_validation:
                continue
            predicted = {"verdict": NEEDS_VALIDATION, "disposition_reason": None, "severity": None}
        else:
            predicted = normalize_prediction(raw)

        m.total += 1
        is_positive_fixture = expected_verdict == CONFIRMED
        if is_positive_fixture:
            m.positives += 1
        else:
            m.negatives += 1

        predicted_positive = predicted["verdict"] == CONFIRMED
        if is_positive_fixture and predicted_positive:
            m.tp += 1
        elif is_positive_fixture:
            m.fn += 1
        elif predicted_positive:
            m.fp += 1
        else:
            m.tn += 1

        if predicted["verdict"] == NEEDS_VALIDATION:
            m.needs_validation += 1

        if is_positive_fixture and hard and fixture_class in hard:
            m.hard_total += 1
            if predicted_positive:
                m.hard_recalled += 1

        if expected_reason:
            m.disposition_checked += 1
            got = predicted.get("disposition_reason")
            if got == expected_reason:
                m.disposition_correct += 1
            elif got in DISPOSITION_ALIASES and DISPOSITION_ALIASES[got] == expected_reason:
                m.disposition_correct += 1
            if got and got not in CANONICAL_DISPOSITIONS and got not in DISPOSITION_ALIASES:
                m.warnings.append(f"{fid}: unknown disposition_reason {got!r}")

        if is_positive_fixture and expected_min_sev and predicted_positive:
            m.severity_checked += 1
            got_sev = predicted.get("severity")
            if got_sev and SEVERITY_RANK.get(str(got_sev), -1) >= SEVERITY_RANK.get(str(expected_min_sev), 0):
                m.severity_satisfied += 1

    return m


def check_thresholds(metrics: Metrics, thresholds: Mapping[str, Any]) -> list[str]:
    """Return a list of human-readable threshold violations (empty == pass).

    Recognized keys: ``min_precision``, ``min_recall``, ``min_f1``,
    ``max_false_positive_rate``, ``max_needs_validation_rate``,
    ``min_hard_bug_recall``, ``min_disposition_accuracy``.
    """
    violations: list[str] = []

    def need_min(key: str, actual: float) -> None:
        if key in thresholds and thresholds[key] is not None:
            if actual < float(thresholds[key]):
                violations.append(f"{key}: {actual:.4f} < required {float(thresholds[key]):.4f}")

    def need_max(key: str, actual: float) -> None:
        if key in thresholds and thresholds[key] is not None:
            if actual > float(thresholds[key]):
                violations.append(f"{key}: {actual:.4f} > allowed {float(thresholds[key]):.4f}")

    need_min("min_precision", metrics.precision)
    need_min("min_recall", metrics.recall)
    need_min("min_f1", metrics.f1)
    need_min("min_hard_bug_recall", metrics.hard_bug_recall)
    need_min("min_disposition_accuracy", metrics.disposition_accuracy)
    need_max("max_false_positive_rate", metrics.false_positive_rate)
    need_max("max_needs_validation_rate", metrics.needs_validation_rate)
    return violations


def thresholds_from_expected(expected: Mapping[str, Any]) -> dict[str, Any]:
    """Derive default CI thresholds from ``evals/expected.json``."""
    em = expected.get("expected_metrics") or {}
    out: dict[str, Any] = {}
    if "false_positive_rate_target_max_pct" in em:
        out["max_false_positive_rate"] = float(em["false_positive_rate_target_max_pct"]) / 100.0
    if "needs_validation_rate_target_max_pct" in em:
        out["max_needs_validation_rate"] = float(em["needs_validation_rate_target_max_pct"]) / 100.0
    if "hard_bug_recall_target_min" in em:
        out["min_hard_bug_recall"] = float(em["hard_bug_recall_target_min"])
    out.setdefault("min_precision", 0.9)
    out.setdefault("min_recall", 0.9)
    return out


def hard_bug_classes(expected: Mapping[str, Any]) -> list[str]:
    em = expected.get("expected_metrics") or {}
    return [str(c) for c in (em.get("hard_bug_classes_covered") or [])]


def format_report(metrics: Metrics, *, title: str = "eval") -> str:
    d = metrics.to_dict()
    lines = [
        f"{title}: {d['total']} fixtures "
        f"({d['positives']} positive / {d['negatives']} negative)",
        f"  TP={d['tp']}  FP={d['fp']}  FN={d['fn']}  TN={d['tn']}  "
        f"NeedsValidation={d['needs_validation']}",
        f"  Precision={d['precision']:.3f}  Recall={d['recall']:.3f}  F1={d['f1']:.3f}",
        f"  FP rate={d['false_positive_rate']:.3f}  "
        f"NeedsValidation rate={d['needs_validation_rate']:.3f}  "
        f"HardBugRecall={d['hard_bug_recall']:.3f} ({d['hard_recalled']}/{d['hard_total']})",
        f"  DispositionAccuracy={d['disposition_accuracy']:.3f}  "
        f"SeverityAccuracy={d['severity_accuracy']:.3f}",
    ]
    if d["missing_predictions"]:
        lines.append(f"  missing predictions: {d['missing_predictions']}")
    for w in d["warnings"]:
        lines.append(f"  warning: {w}")
    return "\n".join(lines)
