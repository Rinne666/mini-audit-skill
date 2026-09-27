# Mini-POI fixture

A minimal PHP target that exhibits the deserialization object-injection
shape that the DokuWiki 2026-07-14a audit uncovered (Issue #4752, CWE-502).

The shape:

- `index.php` parses page text. Lines matching `!plugin! ...` are routed to
  the plugin's `handle()` method.
- The application serializes the parser calls, including the plugin's return
  value, into a cache file.
- A separate request path calls `unserialize()` on the cache file without an
  `allowed_classes` restriction.

The fixture is intentionally tiny. Its expected finding is conditional: an
attacker must be able to influence a plugin return value into an object shape,
and code execution requires a usable gadget class to be loaded. The fixture
locks the trust-boundary shape and the audit-note format; it is not a PoC for
remote code execution.

## What a correct audit produces

The expected output lives in `expected/`:

- `expected/notes.md` — audit notes with a pairing table, source-derived
  coverage units, independent review records, baseline roll-ups, evidence IDs,
  and an explicit incomplete status for unresolved deployment preconditions.
- `expected/finding.md` — a conditional candidate draft with unresolved
  attacker-control and gadget assumptions. It is explicitly not a confirmed
  finding because the independent verifier records `needs_validation`.
- `expected/evidence.jsonl` and `expected/evidence/` — fixture-only captured
  reads and empty searches used to exercise evidence-reference checks.

`runtime/regression.py` runs validate-notes with the evidence ledger and
check-skill-loaded against the fixture. It does not call an LLM and does not
measure audit recall.
