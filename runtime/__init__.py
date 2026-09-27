# runtime -- enforcement primitives for the mini-audit-skill
#
# This is NOT the v2.x Runtime. The v2.x Runtime owned:
#   - L1-L7 phase catalog
#   - search ledger / attack graph / coverage ledger
#   - scheduler / lease / dispatch
#   - phase gates / auto-block
#   - 9 JSON schemas for audit-state / finding / coverage / candidate / phase-result / audit-objective / search-ledger / research-delta / attack-graph
#
# All of those are still gone. This package holds three lightweight checks
# that catch stale skill context and missing output structure. They do not
# prove semantic completeness of an audit or correctness of its verdicts.
#
#   validate_notes.py        pairing and ledger structure check
#   check_skill_loaded.py    session-start load check
#   regression.py            fixture-driven format check

__all__ = ["validate_notes", "check_skill_loaded", "regression"]
