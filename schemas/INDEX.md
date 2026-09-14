# mini-audit-skill schemas

JSON Schema definitions for canonical audit artifacts.

| Schema | Purpose | Spec ref |
|--------|---------|----------|
| `audit-state.schema.json` | Single source of truth for audit run state | §5 |
| `phase-result.schema.json` | Sub-agent return contract | §8 |
| `candidate.schema.json` | Pre-finding candidate record (chamber + scanner) | §13, §28 |
| `finding.schema.json` | Canonical finding model | §11 |
| `coverage-ledger.schema.json` | Coverage state machine | §20 |

These schemas are referenced by:

* `runtime/cli.py` — for finding validation and audit-state validation.
* `runtime/findings.py` — canonical validator (stdlib-only fallback) mirrors `finding.schema.json`.
* `runtime/gates.py` — gate definitions reference these schemas via `GateDefinition.schema_refs`.

When the optional `jsonschema` Python package is installed, schemas are also used directly for stricter validation. The runtime falls back to a minimal type-driven validator otherwise.