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
    "sarif",
    "diff_scope",
    "export",
]

__version__ = "1.1.0"