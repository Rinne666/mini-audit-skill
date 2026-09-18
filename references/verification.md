# Verification

A Verified Fact in the audit notes is a claim that survives a
deliberate attempt to break it. Anything weaker is a Hypothesis.
Verification is the round that promotes one to the other.

## The shape of evidence

Evidence is not "I read the code and it looks wrong." Evidence is:

- A code location with a quoted snippet that proves the bug.
- A runtime trace, log, or response from a proof-of-concept
  experiment that shows the bug.
- A negative control — a near-twin case that should *not* be
  vulnerable, with the same evidence style.

A finding without one of these three is a hypothesis. Move it
back to Hypotheses and run another experiment.

## Four verification methods

**Backward reasoning.** Start from the consequence and trace the
preconditions. The audit is not finished until every precondition
is itself traced to an entry point the attacker can reach. A
precondition the attacker cannot satisfy is a fake finding — the
attack does not work end to end.

**Contradiction search.** For every Verified Fact, write the
strongest plausible disproof argument and check the code to see
whether it holds. Common disproofs:

- "The attacker cannot reach this entry point because of
  middleware X." Read middleware X. Often X exists but does not
  cover this path.
- "The parameter is sanitized before the sink." Read the
  sanitizer. Often it sanitizes a different character set.
- "The check is in the framework layer." Read the framework
  layer. Often the framework delegates back to the application
  and the application overrides it.

**Evidence collection.** When static reading is not enough, run
the experiment. The first experiment that fails proves nothing —
the failure may be the harness. Three experiments with three
different harnesses (different arguments, different timing, different
denial pattern) and three consistent outcomes start to look like
evidence.

**Independent verification.** Hand the hypothesis to a sub-agent
with no prior context: just the audit notes file and the code
under review. If the sub-agent reaches the same conclusion by
a different path, the hypothesis is verified. If the sub-agent
disagrees, the audit is incomplete — go back to Discovery.

## When the model finds nothing

The dangerous case is not when verification fails. It is when
verification cannot start. If the audit has produced hypotheses
without any Verified Facts after two cycles, the model is
generating plausible-sounding guesses, not running an audit. Stop,
shrink the objective, and look harder at a smaller surface.

## Reopen conditions

A Verified Fact moves back to Hypotheses when:

- New evidence shows the precondition is not satisfiable in
  practice.
- A patch removes the bug but the report has already shipped —
  note this in the finding, do not delete it.
- An independent verifier reaches a different conclusion.

A Verified Fact never moves back because the model "is no longer
sure." Doubt without new evidence is not verification.