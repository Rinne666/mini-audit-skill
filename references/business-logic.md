# Security-Relevant Business Process Review

Use this reference when the target implements workflows that change access,
ownership, identity, money or credits, quotas, approvals, account/security
settings, publication state, or other protected assets. This is a security
review of business behavior, not a general product or requirements review.

## Derive invariants from evidence

Do not invent the product's intended policy. Derive candidate invariants from
the sources available in the target: enforced checks, state models, API or
protocol contracts, tests, migration logic, and user-facing flow definitions.
Record which source supports each invariant. Label a reasonable but unproven
interpretation as an inference; it is a hypothesis until confirmed by code,
tests, or an authoritative contract.

Express each invariant in terms of:

> **Actor** may perform **action** on **resource / tenant** only when **state
> and preconditions** hold; the action causes **security-relevant effect** at
> most **once / within a limit**, with **defined failure and recovery behavior**.

Examples of security properties include: only an authorized owner can accept
an invitation; a revoked member cannot complete a pending privileged action;
an approval cannot be replayed; a refund cannot exceed the captured amount; a
one-time token cannot authorize two transitions; a failed multi-step operation
cannot leave a privileged partial state.

## Map a workflow before checking its transitions

For each material flow, capture its source-backed entry points, actors,
protected resources, states, transitions, side effects, and final outcomes.
Trace it across routes, RPC/CLI handlers, callbacks, database writes, queues,
scheduled jobs, external services, retries, and administrative recovery paths.
Follow both directions:

- From a valuable or privileged terminal state back to every writer and
  prerequisite.
- From each transition or side effect forward to every consumer and later
  action it unlocks.

Represent transitions as `actor + current state + action + guard -> next state
+ side effects`. Include alternate entry points that reach the same transition.
Do not count endpoints; cover the security-relevant paths and consumers.

## Challenge the flow with targeted abuse cases

Choose checks that fit the evidence and architecture. At minimum, inspect the
applicable cases below and record which were checked or why they do not apply:

- **Authorization at transition time:** re-check actor, resource ownership,
  tenant, role, and revocation at the operation that commits the change. Do
  not assume an earlier page, token, or workflow step authorizes later steps.
- **State-machine integrity:** attempt skipped, reordered, repeated, reversed,
  stale, or directly-written states; compare sibling endpoints and alternate
  APIs that update the same state.
- **Replay and idempotency:** retry requests, redeliver callbacks/webhooks,
  replay expired or consumed tokens, and repeat jobs after partial completion.
- **Concurrency and atomicity:** inspect check-then-act sequences, duplicate
  approvals, double-spend/refund, lost updates, quota races, and whether
  database transactions cover all security-relevant side effects.
- **Failure and recovery:** follow timeouts, partial failure, rollback,
  compensation, cancellation, retries, migration, restore, and out-of-order
  events. Check whether recovery revalidates authority and state.
- **Limits and quantities:** test zero, negative, maximum, overflow, rounding,
  precision, type coercion, duplicate items, and boundary values where amounts,
  counters, quotas, or counts affect a protected outcome.
- **Separation of duties and lifecycle:** check self-approval, stale
  authorization after role changes, revocation/deletion, account recovery, and
  whether old state or credentials remain usable.
- **Cross-service trust:** identify which component owns the source of truth;
  do not trust client-supplied status, callback claims, cached authorization,
  or queue messages without the validation the receiving transition needs.

For each plausible bypass, write a disproof before trying to confirm it. Read
the exact transition guard and its consumers, then determine whether the
attacker can reach the transition and change another principal's authority,
protected data, funds/credits, quota, security setting, or workflow outcome.
An awkward flow, missing convenience feature, or disagreement with an
unstated product policy is not a security finding by itself.

## Evidence and coverage

Create a `business_logic` coverage unit for each material workflow / attack
surface / trust-boundary combination. Link it from the business-process review
ledger. Keep baseline units such as `authz_sensitive_write` and
`state_cross_endpoint` as separate units when they cover distinct paths; do
not let the new class replace them.

The flow inventory records the source-derived actors, assets, invariants,
transitions, failure/retry cases, abuse cases, evidence IDs, and linked
coverage-unit IDs. If there is no security-relevant business workflow, support
`N/A` with two distinct captured searches over the scoped source inventory and
a concise reason. A blank inventory is not evidence of absence.

The post-wave critic and final reviewer must independently challenge whether
the workflow inventory missed a state writer, transition, alternate actor,
retry/recovery path, side effect, or downstream consumer. A candidate finding
still needs end-to-end code/runtime evidence, a concrete security impact, and
an attempted disproof under `references/verification.md`.
