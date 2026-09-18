# Search Strategy

When the audit notes file is short and the model has no idea where
to look next, ask one question and let it drive the next round:

> What question, if answered, would most likely change the audit
> conclusion?

That question is the only thing that needs an answer before the
next hypothesis is worth writing. Update the **Remaining Questions**
section every time the answer to that question shifts.

## Stop searching when the next answer changes nothing

A common failure: the audit keeps generating plausible-looking
hypotheses long after the remaining questions have stopped
mattering. Two symptoms:

- Hypotheses are getting narrower (different parameter, different
  encoding, different auth state) without producing a new
  permission or capability delta.
- The model is re-reading code it has already read.

When either happens, the audit is saturated. Stop, finalize the
notes, hand over to Report. More searching is not more quality.

## Variant analysis: one bounded pass after each finding

After a finding is proved, run one bounded variant pass on the
nearby code: what other code paths are shaped like the one just
proved? The pass ends when it has either (a) found a new affected
surface that the audit has not covered, or (b) walked the
sibling patterns without producing a new permission or capability
delta. Stop the branch either way — do not loop on the same
class.

Do not delay the report to find every variant. The original is
the finding; variants are next, not a gate.

## Chain search: connect one delta to the next

A bug that grants a capability can connect to a bug that consumes
that capability. The chain is a higher-value finding than either
single bug, because the attacker now reaches a consequence that
no single bug produced.

For every Verified Fact that grants a capability, search the rest
of the audit for a sink that consumes that capability. The result
either confirms a chain or rules it out — both are progress.

## Sub-agent boundaries

Sub-agents are not free. Use them when:

- A hypothesis needs independent verification by a path that
  does not share the model's prior reasoning.
- A bounded search (variant hunt, chain search) can run in
  parallel with the main audit.
- An experiment needs to run in a clean harness (PoC execution,
  for example).

Do not use a sub-agent to "look at the code." The model can read
faster than a sub-agent can be dispatched.

## Trust boundary check before each round

Before every Discover or Verify round, re-read the Attack Surface
section of the notes file. If a new boundary has surfaced, add it.
If an old boundary has been disproved, remove it. The audit is
only as good as its map of where the attacker can reach.