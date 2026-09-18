# Audit Notes — {target}

> One Markdown file. The whole state of this audit. Edit it in place,
> every round. No IDs, no schema, no transactions, no generator.
> The file *is* the canonical state — make it readable to a stranger.

---

## Objective

What is being audited, who is the attacker, what is the highest-value
target capability, what trust boundary does the attacker start from.
Rewrite this section when the objective shifts.

## Attack Surface

Entry points and trust boundaries the attacker can reach. One bullet
per surface, with the file path and the rough data flow. When the
model reads a new surface during Discover, add a bullet.

## Verified Facts

Statements the audit has already proven with code or runtime evidence.
Each fact names the file path, the line, and the experiment (if any)
that proves it. A fact without a pointer is just a hypothesis — move
it to Hypotheses.

## Hypotheses

Plausible vulnerability hypotheses the audit is currently trying to
prove or disprove. One bullet each, written as a single sentence of
the form:

> If `<condition>` is true at `<location>`, then `<attacker
> capability>` follows because `<data path>`.

State the disproof condition alongside the hypothesis. If you cannot
state the disproof, the hypothesis is too vague to test — rewrite it.

## Blocked Leads

Attack chains that are blocked on a single unverified precondition,
where the precondition might become verifiable later. Each lead says
exactly what would unblock it. Do not lose this list when the lead
seems unproductive — that is the point.

## Remaining Questions

The one question, if answered, would most likely change the audit
conclusion. Update this list as the audit progresses. When the answer
matters less than it used to, replace it.

---

## How to use this file

1. **Scope round.** Fill in Objective + Attack Surface. Stop when the
   model can name the highest-value target capability and the boundary
   the attacker starts from.
2. **Discover round.** Add Hypotheses. Each hypothesis names its
   disproof. Read code, trace data flow, read references, ask an
   independent sub-agent. When evidence proves a hypothesis, move it
   to Verified Facts. When evidence disproves it, delete it.
3. **Verify round.** For every Verified Fact, ask: is the evidence
   strong enough that another auditor, with no prior context, would
   agree? If not, run another experiment or escalate to an
   independent sub-agent. Move weak claims to Hypotheses.
4. **Report round.** Every finding in the final report must trace
   back to a Verified Fact in this file. If it does not, it is not
   ready.

The model can jump between rounds. The file does not enforce a
state machine. The reviewer enforces it by reading.