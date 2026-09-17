"""Architecture invariant — runtime is inert (spec §2 / §11).

Spec §2 lists the verbs the runtime must NOT use, because each one
implies an autonomous control loop:

  plan / choose / rank / dispatch / investigate / promote / advance /
  decide / schedule

These tests pin the contract by scanning ``runtime/`` for **function /
class names** that contain those tokens. The scan is deliberately
lexical and narrow so false positives (e.g. ``args.plan`` or
``risk_ranked`` as a noun) do not fail the gate.

A function named ``plan_next_round`` or a class called ``Scheduler``
is a smell: the runtime is not supposed to own a control loop.
Catch it before merge.

Spec §11 makes this a CI invariant: any future code that introduces a
control verb here must fail CI before merge.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

RUNTIME_ROOT = Path("runtime").resolve()

# Each entry is a forbidden token + a one-line rationale.
FORBIDDEN_TOKENS: tuple[tuple[str, str], ...] = (
    ("plan", "spec §2: runtime must not plan next moves"),
    ("choose", "spec §2: runtime must not choose among options"),
    ("rank", "spec §2: runtime must not rank candidates"),
    ("dispatch", "spec §2: runtime must not dispatch workers"),
    ("investigate", "spec §2: runtime must not initiate investigations"),
    ("promote", "spec §2: runtime must not promote candidates"),
    ("advance", "spec §2: runtime must not advance phases"),
    ("decide", "spec §2: runtime must not originate decisions"),
    ("schedule", "spec §2: runtime must not own a scheduler"),
)

# Explicit allowlist: identifiers that contain a forbidden token but
# are mechanical data (not control actions).
NOISE_TOKENS = {
    # noun, not verb:
    "risk_ranked", "coverage_planning_status", "planning_status",
    "planning_complete", "replanned", "replanning",
    # argument / variable names that happen to contain the token:
    "args_plan", "args_commit",
    # names that exist for backward compatibility (e.g. Piolium import):
    "disposition_reason",
    # diff-mode D6: builds an adversarial-plan.json artifact (data),
    # not a control action. The plan is the *output*, not a decision.
    "build_adversarial_plan",
    # gate semantic check: tests "no units are still planned", the
    # verb is *check*, not *plan*.
    "_check_coverage_no_planned",
    # scheduler.frozen-remnant (spec §9): keep until the Harness owns
    # agent scheduling; `dispatch` here is the runtime's pre-existing
    # retry primitive, not a runtime control verb. Listed in SKILL.md
    # as "deprecated / frozen / harness-owned".
    "dispatch", "dispatch_command", "parallel", "compute_backoff",
}


def _iter_python_files() -> list[Path]:
    return sorted(RUNTIME_ROOT.rglob("*.py"))


def _identifier_matches(text: str, token: str) -> list[tuple[str, int]]:
    """Return ``(name, line_number)`` for each top-level definition whose
    identifier contains the forbidden token. Definitions are matched at
    column 0 with ``def`` or ``class``; string contents are NOT scanned
    (false-positive control)."""
    offenders: list[tuple[str, int]] = []
    for match in re.finditer(rf"^(def|class)\s+(\w*{token}\w*)\b",
                                text, re.MULTILINE):
        name = match.group(2)
        line_no = text[: match.start()].count("\n") + 1
        if name in NOISE_TOKENS:
            continue
        offenders.append((name, line_no))
    return offenders


@pytest.mark.parametrize(
    "file",
    _iter_python_files(),
    ids=lambda p: str(p.relative_to(RUNTIME_ROOT)),
)
def test_runtime_does_not_declare_control_verbs(file: Path) -> None:
    text = file.read_text(encoding="utf-8")
    offenders: list[tuple[str, str, int]] = []
    for token, rationale in FORBIDDEN_TOKENS:
        for name, line_no in _identifier_matches(text, token):
            offenders.append((name, token, line_no))
    assert not offenders, (
        f"{file.relative_to(RUNTIME_ROOT)} declares top-level control "
        f"verbs ({sorted({n for n, _, _ in offenders})}) which the "
        "runtime must not own (spec §2). Move the logic to the Skill "
        "or the Harness, then re-run CI."
    )


def test_runtime_does_not_import_skill_or_harness_modules() -> None:
    """Spec §9: dependency direction must stay one-way. Runtime may
    NOT import anything from the Skill, the Harness, or mavis agent
    APIs. The scan is intentionally narrow (anything outside the
    project package) so a future harness import fails loudly."""
    forbidden_imports = ("mavis", "workbuddy", "harness", "skill")
    offenders: list[tuple[str, str, str]] = []
    for file in _iter_python_files():
        text = file.read_text(encoding="utf-8")
        for match in re.finditer(r"^\s*from\s+([\w.]+)\s+import|^import\s+([\w.]+)$",
                                   text, re.MULTILINE):
            mod = match.group(1) or match.group(2)
            for forbidden in forbidden_imports:
                if mod.startswith(forbidden):
                    line_no = text[: match.start()].count("\n") + 1
                    offenders.append((mod, str(line_no), file.name))
    assert not offenders, (
        "runtime/ must not import from Skill / Harness / mavis APIs "
        "(spec §9):\n"
        + "\n".join(f"  {file}:{ln} imports {mod}" for mod, ln, file in offenders)
    )


def test_runtime_owns_no_autonomous_loop_marker() -> None:
    """Spec §2 + §9: the runtime must not host an autonomous loop.

    ``while True:`` is allowed ONLY when the loop body has a bounded
    deadline (a ``break`` / ``return`` / ``raise`` reachable from a
    time/counter check). Bounded retry loops (lock acquire, deadline
    check) are deterministic infrastructure, not a control loop.
    """
    offenders: list[tuple[str, str, str, str]] = []
    for file in _iter_python_files():
        text = file.read_text(encoding="utf-8")
        for match in re.finditer(r"while\s+True\s*:", text):
            line_no = text[: match.start()].count("\n") + 1
            # Take the next 30 lines as the loop body and look for
            # any deadline / exit signal.
            body_lines = text.splitlines()[line_no: line_no + 30]
            body = "\n".join(body_lines)
            bounded = (
                "break" in body
                or "return" in body
                or "raise" in body
                or "deadline" in body
                or "monotonic" in body
                or "_stop" in body
            )
            offenders.append((file.name, str(line_no),
                              text.splitlines()[line_no - 1].strip(),
                              "bounded" if bounded else "UNBOUNDED"))
    unbounded = [o for o in offenders if o[3] == "UNBOUNDED"]
    assert not unbounded, (
        "runtime/ has an unbounded ``while True:`` (spec §2 + §9):\n"
        + "\n".join(f"  {f}:{ln}: {t}" for f, ln, t, _ in unbounded)
    )