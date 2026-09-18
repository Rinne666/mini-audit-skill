"""mini-audit runtime — deterministic layer.

This package implements the deterministic runtime layer described in
`mini-audit-skill Runtime Hardening Implementation Spec v1.0`.

Layer boundaries (Skill-First Refactor v1):

* Reasoning Layer (LLM agents) — produces hypothesis, trace, debate, candidate drafts.
* Policy Layer (this skill's `references/`, not Python) — permission-delta judging,
  and since Search Governance v1 the "what to investigate next" rules
  (`references/search-governance.md`).
* Deterministic Layer (this package) — owns state, schema, gates, fingerprinting,
  coverage accounting, and export. The LLM "I am done" never advances state on
  its own: phase completion requires the runtime to validate the expected
  artifacts, parse them, schema-validate them, and pass gates.

What is deliberately *not* here: agent dispatch, concurrency, retries, worker
lifecycle and recovery. Those belong to the agent harness. The process-group
deadline primitive lives in `process_control` and is consumed by the sandbox
policy. See SKILL.md § "Skill / Harness boundary" for the per-module
classification.

Inside the deterministic layer, Search Governance v1 adds a second plane:

* control plane — `objective` (what the audit is trying to prove; canonical and
  immutable once L1 completes).
* research plane — `research_state` (what the search knows, suspects, is blocked
  on and intends next), `attack_graph` (capability conversions, plus the
  traversal the ranking rules and the closure check both need), and `search_lock`
  (one cross-process lock over the research artifacts).
* verification — `search_closure` (does a confirmed finding's reported chain
  actually reach?) and `search_saturation` (the completion floor and the
  remaining research debt). Both are read-only checkers used by the L7 gate.

Agents still write only into `agents/<id>/scratch/`; a research delta is the
one channel through which they reach the research plane, and it applies whole
or not at all. The orchestrator is the single writer of canonical state.

Public entry points:

* `cli.main` — the `mini-audit-runtime` CLI dispatcher.
* `state.AuditState` — canonical audit-state object.
* `findings.FindingStore` — canonical findings.json store.
* `coverage.CoverageLedger` — coverage-ledger state machine.
* `gates.GateRunner` — phase gate executor.
* `fingerprint.compute_fingerprint` — stable SHA-256 finding fingerprint.
* `source_identity.SourceIdentity` — git-derived source identity.
* `process_control.run_command_with_timeout` — process-group hard-timeout
  primitive. The only deterministic safety primitive about processes the
  runtime owns.
* `sarif.SarifNormalizer` — scanner output → candidate records.
* `diff_scope.DiffScope` — changed-symbol caller tracing.
* `export.Exporter` — JSON / Markdown / SARIF export.
* `atomic_io` — atomic write primitive (write tmp + fsync + rename).
* `objective` — audit-objective.json load / validate / lockstep revision.
* `research_state` — search-ledger.json and the research-delta transaction.
* `attack_graph` — attack-graph.json data layer + traversal + queries.
* `search_closure` — does a reported capability chain actually close?
* `search_saturation` — the two-condition completion gate and the debt report.
* `search_lock.SearchGovernanceLock` — the Search Governance write lock.
* `snapshot` — read-only derived view of the audit state for the model.

The package is intentionally stdlib-only (Python 3.9+). External JSON-schema
validation is performed via the `jsonschema` package when available; otherwise
the runtime falls back to a minimal type-driven validator that is sufficient
for the canonical schemas shipped in this skill.
"""

from __future__ import annotations

__all__ = [
    "atomic_io",
    "cli",
    "state",
    "findings",
    "fingerprint",
    "coverage",
    "gates",
    "schema",
    "source_identity",
    "process_control",
    "sandbox",
    "sandbox_backend",
    "sarif",
    "diff_scope",
    "export",
    "objective",
    "research_state",
    "attack_graph",
    "search_lock",
    "search_closure",
    "search_saturation",
    "snapshot",
]

__version__ = "1.4.0"