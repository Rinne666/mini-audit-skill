"""v1.1.1 §19 — gate coverage beyond balanced mode.

The v1.1 review found that only ``balanced`` (L1–L7) declared deterministic
gates, so ``lite`` / ``deep`` / ``confirm`` / ``judge`` / ``longshot`` /
``reinvest`` / ``revisit`` phases advanced on the agent's word alone. These
tests pin both halves of the fix:

* every phase with a *documented dedicated artifact* now has a gate, and the
  gate actually passes on a well-formed artifact and fails without it;
* the phases that remain ungated are listed explicitly, so the gap is a
  declared contract instead of an unstated assumption.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from runtime.gates import (
    DEFAULT_PHASE_GATES,
    GateError,
    GateRunner,
    gate_for,
    gated_phases,
    has_gate,
    ungated_phases,
)

BIG = "x" * 200  # comfortably above every min_bytes used by the new gates
AUDIT = "mini-audit"


def _write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _write_json(root: Path, rel: str, payload: object) -> None:
    _write(root, rel, json.dumps(payload))


#: phase -> callable(root) that materialises the gate's required artifacts.
#: Mirrors the "Artifact gate" table in SKILL.md. Only the phases added in
#: v1.1.1 are listed; L1–L7 already have dedicated tests in test_gates.py.
FIXTURES: dict[str, object] = {
    # --- lite ---
    "Q0": lambda r: (
        _write(r, f"{AUDIT}/attack-surface/recon-report.md", BIG),
        _write(r, f"{AUDIT}/attack-surface/candidates-summary.md", "summary"),
        _write(r, f"{AUDIT}/attack-surface/candidates.jsonl", '{"id":"c1"}\n'),
    ),
    "Q1": lambda r: _write(r, f"{AUDIT}/attack-surface/lite-q1-summary.md", "q1"),
    "Q2": lambda r: (
        _write(r, f"{AUDIT}/attack-surface/lite-q2-summary.md", "q2"),
        _write(r, f"{AUDIT}/attack-surface/unauthenticated-surface.md", "surf"),
    ),
    "Q3": lambda r: _write_json(r, f"{AUDIT}/attack-surface/lite-consolidation-manifest.json", {"promoted": []}),
    "Q4": lambda r: _write(r, f"{AUDIT}/attack-surface/lite-verification-summary.md", "q4"),
    # --- deep ---
    "P1": lambda r: _write(r, f"{AUDIT}/attack-surface/advisories.md", "adv"),
    "P1.5": lambda r: _write(r, f"{AUDIT}/attack-surface/env-provisioning.md", "env"),
    "P2": lambda r: _write_json(r, f"{AUDIT}/attack-surface/intent-corpus.json", {"intents": ["a"]}),
    "P3": lambda r: _write(r, f"{AUDIT}/attack-surface/knowledge-base-report.md", BIG),
    "P8": lambda r: _write(r, f"{AUDIT}/probe-workspace/p1/probe-summary.md", "probe"),
    "P9": lambda r: _write(r, f"{AUDIT}/attack-surface/spec-gap.md", "gap"),
    "P10": lambda r: _write_json(r, f"{AUDIT}/chamber-workspace/c1/debate.json", {"debate_status": "closed"}),
    "P12": lambda r: _write(r, f"{AUDIT}/attack-surface/variant-candidates.md", "variants"),
    "P13": lambda r: _write(r, f"{AUDIT}/findings/F1-slug/poc.sh", "#!/bin/sh\n"),
    "P14": lambda r: _write(r, f"{AUDIT}/findings/F1-slug/report.md", "report"),
    "P15": lambda r: _write(r, f"{AUDIT}/final-audit-report.md", BIG),
    "P16": lambda r: _write(r, f"{AUDIT}/findings/F1-slug/patch-bypass.md", "bypass"),
    "P17": lambda r: _write_json(r, f"{AUDIT}/attack-surface/cleanup-manifest.json", {"removed": []}),
    # --- longshot ---
    "X1": lambda r: _write_json(r, f"{AUDIT}/longshot/targets.json", {"targets": []}),
    "X2": lambda r: _write(r, f"{AUDIT}/longshot/findings-draft/longshot-abc-001-a.md", "draft"),
    "X3": lambda r: _write(r, f"{AUDIT}/longshot/longshot-summary.md", "summary"),
    # --- revisit ---
    "R0": lambda r: _write_json(r, f"{AUDIT}/attack-surface/intent-corpus.json", {"intents": ["a"]}),
    # --- reinvest ---
    "I2": lambda r: _write(r, f"{AUDIT}/findings/F1-slug/wave-2-verdict.md", "verdict"),
    # --- confirm ---
    "V1": lambda r: _write_json(r, f"{AUDIT}/confirm-workspace/findings-inventory.json", {"findings": []}),
    "V7": lambda r: _write(r, f"{AUDIT}/confirmation-report.md", BIG),
    # --- judge ---
    "J1": lambda r: _write(r, f"{AUDIT}/findings/F1-slug/judge-verdict.md", "verdict"),
    "J2": lambda r: _write(r, f"{AUDIT}/judge-report.md", BIG),
    # --- knowledge-base ---
    "K1": lambda r: _write_json(r, f"{AUDIT}/attack-surface/sbom.json", {"components": []}),
    "K2": lambda r: (
        _write(r, f"{AUDIT}/attack-surface/knowledge-base-report.md", BIG),
        _write(r, f"{AUDIT}/attack-surface/unauthenticated-surface.md", "surf"),
    ),
}

#: Phases deliberately left ungated, per mode. Update this set *and* the
#: SKILL.md "Gate coverage" table together — never silently.
EXPECTED_UNGATED: dict[str, set[str]] = {
    "lite": set(),
    "balanced": set(),
    "deep": {"P4", "P5", "P6", "P7", "P11"},
    "confirm": {"V1.5", "V2", "V3", "V4", "V5", "V6"},
    "revisit": {"R5", "R7", "R8", "R9", "R10", "R10k", "R11", "R11b", "R11c"},
    "merge": {"M1", "M2", "M3", "M4", "M5", "M6", "M7"},
    "longshot": set(),
    "reinvest": {"I1", "I3"},
    "knowledge-base": {"KB0"},
    "judge": set(),
}


@pytest.mark.parametrize("phase", sorted(FIXTURES))
def test_new_gate_passes_on_wellformed_artifact(tmp_path: Path, phase: str) -> None:
    FIXTURES[phase](tmp_path)  # type: ignore[operator]
    result = GateRunner(workdir=tmp_path).run(gate_for(phase), semantic_data={}, ctx={"current_phase": phase})
    assert result.passed, [(f.kind, f.label, f.message) for f in result.failures]


@pytest.mark.parametrize("phase", sorted(FIXTURES))
def test_new_gate_fails_when_artifact_absent(tmp_path: Path, phase: str) -> None:
    """No artifacts on disk -> the gate must not pass. Fail closed."""
    result = GateRunner(workdir=tmp_path).run(gate_for(phase), semantic_data={}, ctx={"current_phase": phase})
    assert not result.passed, f"{phase} passed with an empty workspace"


def test_every_fixture_phase_is_gated() -> None:
    for phase in FIXTURES:
        assert has_gate(phase), f"{phase} has a fixture but no gate"


def test_coverage_of_new_gates_is_complete() -> None:
    """Every fixture phase must be reachable through gate_for()."""
    for phase in FIXTURES:
        assert gate_for(phase).name == phase


def test_ungated_phases_match_the_declared_contract() -> None:
    """Drift guard: the ungated set is a deliberate, named list."""
    for mode, expected in EXPECTED_UNGATED.items():
        assert set(ungated_phases(mode)) == expected, mode


def test_fully_gated_modes_have_no_ungated_phase() -> None:
    for mode in ("lite", "balanced", "longshot", "judge"):
        assert ungated_phases(mode) == [], mode
        assert len(gated_phases(mode)) > 0, mode


def test_gate_for_still_raises_for_a_truly_unknown_phase() -> None:
    with pytest.raises(GateError):
        gate_for("ZZZ")


def test_default_gate_table_is_not_accidentally_empty() -> None:
    # Guards against a refactor that drops the appended block.
    assert len(DEFAULT_PHASE_GATES) >= 38
    for phase in ("Q0", "P1.5", "V7", "J2", "X3", "K2", "I2", "R0"):
        assert phase in DEFAULT_PHASE_GATES
