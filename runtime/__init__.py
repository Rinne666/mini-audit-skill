# runtime -- enforcement primitives for the mini-audit-skill
#
# This is NOT the v2.x Runtime. The v2.x Runtime owned:
#   - L1-L7 phase catalog
#   - search ledger / attack graph / coverage ledger
#   - scheduler / lease / dispatch
#   - phase gates / auto-block
#   - 9 JSON schemas for audit-state / finding / coverage / candidate / phase-result / audit-objective / search-ledger / research-delta / attack-graph
#
# All of those are still gone. This package holds three primitives that
# close the two distinct failure modes identified after the React 19 long-
# chain incident (post-mortem 2026-09-25):
#
#   1. spec bug  -> closed by prompt fixes (Guard rule, Absence recheck,
#      Coverage rule, Downgrade symmetry, Entry-point census, Coverage
#      paragraph, Universal-negative guardrail) -- already in SKILL.md.
#
#   2. enforcement gap -> closed by three primitives here:
#
#        validate_notes.py        pairing-table schema check (write-time)
#        check_skill_loaded.py    session-start load check
#        regression.py            fixture-driven self-test
#
# The agent / model layer is doing its job; the gap was that nothing on
# disk was checking the agent's output. This package adds the check.

__all__ = ["validate_notes", "check_skill_loaded", "regression"]