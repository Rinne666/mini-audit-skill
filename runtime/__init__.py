# runtime -- enforcement primitives for the mini-audit-skill
#
# This is NOT the v2.x Runtime. The v2.x Runtime owned:
#   - L1-L7 phase catalog
#   - general-purpose search ledger / attack graph / phase-owned coverage database
#   - scheduler / lease / dispatch
#   - phase gates / auto-block
#   - 9 JSON schemas for audit-state / finding / coverage / candidate / phase-result / audit-objective / search-ledger / research-delta / attack-graph
#
# Those full orchestration components are still absent. The audit notes now
# hold lightweight source-derived coverage units and review records. This
# package has three lightweight checks plus evidence and ID helpers; none
# proves semantic completeness or correctness of verdicts.
#
#   validate_notes.py        pairing and ledger structure check
#   check_skill_loaded.py    session-start load check
#   regression.py            fixture-driven format check
#   evidence_log.py           bounded source read/search capture
#   coverage_id.py            stable coverage-unit ID generator

__all__ = ["validate_notes", "check_skill_loaded", "regression", "coverage_id"]
