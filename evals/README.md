# mini-audit-skill evals

Three classes of eval fixtures (Spec §38):

* `positive/` — real vulnerabilities that **must** produce `verdict=confirmed`
* `negative/` — non-vulnerabilities that **must** produce `verdict=rejected` with the named `disposition_reason`
* `ambiguous/` — edge cases that **must** produce `verdict=needs_validation`

`expected.json` aggregates the expected verdicts so a future eval harness can
diff the LLM output against this canonical answer set.

Each fixture is a JSON file containing:

```json
{
  "id": "EVAL-POS-001",
  "name": "...",
  "class": "idor",
  "input": { ...the candidate draft or finding... },
  "expected_verdict": "confirmed",
  "expected_disposition_reason": null,
  "expected_min_severity": "high",
  "rationale": "Why this is a real bug — short, evidence-grounded."
}
```

The harness:

1. For each positive fixture, runs Review Chamber + Technical Verifier + Permission-Delta judge (LLM responsibility); asserts verdict=confirmed.
2. For each negative fixture, runs the same chain; asserts verdict=rejected and the named disposition_reason.
3. For each ambiguous fixture, asserts verdict=needs_validation (never promoted to confirmed without sandbox reproduction).

A v1 smoke run covers at least 10 positive / 15 negative / 5 ambiguous fixtures. Initial pass target: **FP rate significantly lower than current mini-audit**, not highest finding count.