"""mini-audit runtime — deterministic layer.

This package implements the deterministic runtime layer described in
`mini-audit-skill Runtime Hardening Implementation Spec v1.0`.

Layer boundaries:

* Reasoning Layer (LLM agents) — produces hypothesis, trace, debate, candidate drafts.
* Policy Layer (permission-delta, verification methodology) — judges candidates.
* Deterministic Layer (this package) — owns state, gates, schema, fingerprinting,
  coverage accounting, scheduling, and export. The LLM "I am done" never
  advances state on its own. Phase completion requires the runtime to validate
  expected artifacts, parse them, schema-validate them, and pass gates.

Inside the deterministic layer, Search Governance v1 adds a second plane:

* control plane — `objective` (what the audit is trying to prove; canonical and
  immutable once L1 completes).
* research plane — `research_state` (what the search knows, suspects, is blocked
  on and intends next), `attack_graph` (capability conversions), and
  `search_lock` (one cross-process lock over the research artifacts).

Agents still write only into `agents/<id>/scratch/`; a research delta is the
one channel through which they reach the research plane, and it applies whole
or not at all.

Public entry points:

* `cli.main` — the `mini-audit-runtime` CLI dispatcher.
* `state.AuditState` — canonical audit-state object.
* `findings.FindingStore` — canonical findings.json store.
* `coverage.CoverageLedger` — coverage-ledger state machine.
* `gates.GateRunner` — phase gate executor.
* `fingerprint.compute_fingerprint` — stable SHA-256 finding fingerprint.
* `source_identity.SourceIdentity` — git-derived source identity.
* `scheduler.Scheduler` — concurrency lease + timeout + retry/backoff.
* `sarif.SarifNormalizer` — scanner output → candidate records.
* `diff_scope.DiffScope` — changed-symbol caller tracing.
* `export.Exporter` — JSON / Markdown / SARIF export.
* `atomic_io` — atomic write primitive (write tmp + fsync + rename).
* `objective` — audit-objective.json load / validate / lockstep revision.
* `research_state` — search-ledger.json and the research-delta transaction.
* `attack_graph` — attack-graph.json data layer (ids, consistency, bootstrap).
* `search_lock.SearchGovernanceLock` — the Search Governance write lock.

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
    "scheduler",
    "sandbox",
    "sandbox_backend",
    "sarif",
    "diff_scope",
    "export",
    "objective",
    "research_state",
    "attack_graph",
    "search_lock",
]

__version__ = "1.2.0"