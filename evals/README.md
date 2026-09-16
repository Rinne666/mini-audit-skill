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

`run.py` scores the corpus and `score.py` fails CI when a threshold regresses.

# Long-horizon eval (`long_horizon/`)

A second, **separate** evaluator — it does not extend the classification corpus
above, because it measures something else entirely. Run it with:

```bash
python evals/long_horizon_run.py            # human summary, exit 1 on a threshold miss
python evals/long_horizon_run.py --json     # full report
python evals/long_horizon_run.py --scenario CHAIN-001
```

## What it measures

Each scenario is a scripted sequence of research deltas — the material an agent
would have submitted across several audit rounds — replayed against a real
audit root. The runtime's handling of that state is scored by three metrics:

| Metric | Question it answers |
|---|---|
| `premature_rejection_rate` | Was a locally valid primitive dropped because nothing in the research state preserved it? |
| `blocked_path_reopen_rate` | When the assumption a blocker rested on was disproved, did the blocked path reopen? |
| `chain_completion_recall` | Did the split chain end up verified-reachable as a whole? |

A scenario declares its own `oracle` (which candidates should survive, which
blocked paths should reopen, which chains should close) and its own
`thresholds`; a miss fails CI.

## What it does not measure

**Not** vulnerability-discovery performance. No model is run, and no scenario
compares two ways of running the same audit. These numbers describe whether the
state machine kept its promises about long-lived research state. Claiming a
finding-rate improvement from them would be claiming that a state machine made
an analyst smarter.

## The simulated verdict

The oracle says which candidates *should* survive; deciding that one was
rejected needs a policy. The policy is stated in terms of research state the
**runtime** maintains:

> keep a candidate iff a blocked path records why it cannot be used yet, or a
> capability it requires (or grants) is now reachable

Every clause reads the ledger and graph, never the scenario file — so a runtime
that loses a blocker, fails to reopen one, or never connects the chain will
reject a candidate the oracle expected to survive. That is what makes the
metric a test of the runtime rather than of the evaluator. In a real audit this
judgement belongs to the Review Chamber; here it is a stand-in with the same
contract.

## Fixture layout

A fixture is a **directory**, because its sources have to be real:

```text
evals/long_horizon/<fixture>/
    A.py  B.py  C.py     the three thirds of the chain
    scenario.json        objective, candidates, delta sequence, oracle, thresholds
```

The deltas cite `file:line` evidence, and the evaluator copies the declared
sources into the replay root and checks every such reference resolves to a real
line before anything is replayed. A fixture whose sources drifted would
otherwise still pass — demonstrating the chain against code that no longer
exists. The count of resolved references is printed with the metrics, so a check
that quietly stopped matching is visible rather than green.

## First fixture — `chain-001`

`chain-001` splits one attack chain across three files:

| File | Third of the chain | Why it is not a finding alone |
|---|---|---|
| `A.py` | the validation bypass — the import path reaches the report query without coercing the filter | a missing validation with no dangerous sink; all it can do with the value is pass it on |
| `B.py` | the query primitive — the report SQL is built by concatenation | every route reaching it coerces the filter to a list of integers first, so it cannot be driven |
| `C.py` | the privileged transition — a role is copied out of a report row onto the session | the row comes from the query, so while the query is integer-only the role is the database's choice |

The replay submits only research deltas. It checks that the runtime keeps `B.py`'s
primitive alive while it is blocked rather than rejecting it, reopens the blocked
path when `A.py`'s bypass disproves the assumption the blocker rested on, and ends
with a verified path from the objective's initial capability to its goal.
