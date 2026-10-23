#!/usr/bin/env python3
"""Unit tests for the adjudication derivations in validate_adjudication.py.

The two derivations are the core of the framework:

  validity      any refuted -> does_not_hold
                any fixed    -> already_fixed
                an unresolved defect/reachability/consequence
                            -> needs_more_evidence
                an unresolved precondition alone -> holds
                all confirmed                       -> holds

  acceptability declared_and_consistent -> decline
                attacker_only + present      -> accept
                attacker_only + absent       -> accept_after_rewrite
                third_party  + present       -> accept_after_rewrite
                otherwise                    -> decline

These tests check the derivations directly, because a wrong derivation
silently changes the meaning of every verdict in the file.

Run: python runtime/test_validate_adjudication.py
Exit codes: 0 all pass, 1 a test failed.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from validate_adjudication import (  # noqa: E402
    _derive_acceptability,
    _derive_validity,
)

failures: list[str] = []


def check(label: str, got: object, expected: object) -> None:
    if got == expected:
        print(f"OK:   {label} => {got!r}")
    else:
        print(f"FAIL: {label} => {got!r}, expected {expected!r}")
        failures.append(label)


def v(types: list[str], verdicts: list[str]) -> str:
    return _derive_validity(types, verdicts)


# --- validity derivation -------------------------------------------------

check(
    "all confirmed",
    v(["defect", "reachability"], ["confirmed", "confirmed"]),
    "holds",
)
check(
    "one refuted",
    v(["defect", "reachability"], ["confirmed", "refuted"]),
    "does_not_hold",
)
check(
    "unresolved defect blocks",
    v(["defect", "reachability"], ["confirmed", "unresolved"]),
    "needs_more_evidence",
)
check(
    "unresolved reachability blocks",
    v(["reachability", "consequence"], ["unresolved", "confirmed"]),
    "needs_more_evidence",
)
check(
    "unresolved consequence blocks",
    v(["consequence"], ["unresolved"]),
    "needs_more_evidence",
)
check(
    "unresolved precondition alone does not block",
    v(["defect", "reachability", "consequence", "precondition"],
      ["confirmed", "confirmed", "confirmed", "unresolved"]),
    "holds",
)
check(
    "one fixed",
    v(["fixed", "confirmed"], ["fixed", "confirmed"]),
    "already_fixed",
)
check(
    "refuted beats unresolved",
    v(["defect", "reachability"], ["unresolved", "refuted"]),
    "does_not_hold",
)
check(
    "refuted beats fixed",
    v(["defect", "defect"], ["fixed", "refuted"]),
    "does_not_hold",
)
check(
    "fixed beats unresolved",
    v(["defect", "precondition"], ["unresolved", "fixed"]),
    "already_fixed",
)
check("no assertions", v([], []), "unadjudicated")

# --- acceptability derivation --------------------------------------------

check(
    "attacker_only + present + not_declared",
    _derive_acceptability("attacker_only", "not_declared", "present"),
    "accept",
)
check(
    "attacker_only + present + declared_and_violated",
    _derive_acceptability("attacker_only", "declared_and_violated", "present"),
    "accept",
)
check(
    "attacker_only + absent",
    _derive_acceptability("attacker_only", "not_declared", "absent"),
    "accept_after_rewrite",
)
check(
    "declared_and_consistent always declines",
    _derive_acceptability("attacker_only", "declared_and_consistent", "present"),
    "decline",
)
check(
    "operator dependent declines",
    _derive_acceptability("requires_operator_decision", "not_declared", "present"),
    "decline",
)
check(
    "ambient declines",
    _derive_acceptability("requires_ambient_state", "not_declared", "present"),
    "decline",
)
check(
    "third party with divergence needs rewrite",
    _derive_acceptability("requires_third_party_misconfiguration", "not_declared", "present"),
    "accept_after_rewrite",
)
check(
    "third party without divergence declines",
    _derive_acceptability("requires_third_party_misconfiguration", "not_declared", "absent"),
    "decline",
)

if failures:
    print(f"\n{len(failures)} test(s) FAILED: {failures}")
    raise SystemExit(1)
print("\nall derivation tests passed")
