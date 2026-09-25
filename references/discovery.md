# Discovery

How to read a codebase so plausible vulnerabilities surface. The model
is doing the reasoning — this reference names the methods that
actually pay off when nothing is yet known.

## Read for entry points, not for bugs

Start from where attacker-controlled data enters the application:
route handlers, RPC entry points, CLI parsers, webhook receivers,
background jobs that consume queues, file uploads, deserialization
sinks. Read those until the data path is clear. Do not start by
reading the database.

For every entry point, name:

- The file path and line range of the handler.
- The trust boundary it crosses (network → app, app → privileged
  syscall, app → another service).
- The shape of the input at entry (raw body, parsed struct,
  authenticated principal).

The goal of Discovery is a map of the attack surface relevant to
the audit objective, not an exhaustive catalog of every endpoint.
Expand the map when evidence reveals a new reachable boundary.
A static check-list of every handler biases the audit toward
counting rather than finding.

## Read backward from sinks

Once entry points are mapped, walk backward from sinks that grant
attacker value: SQL queries, shell exec, file path joins, deserialis-
   ation, outbound HTTP, secret material, role/permission writes.
For each sink, ask: how could an entry point reach me with an
attacker-controlled value at the parameter the sink binds?

The model that wins audits is the one that finds the data path
**between** entry and sink that no one else looked at.

## Trace across endpoints, not just across files

A common failure is reading each endpoint as a single request -> sink
chain. High-value bugs are usually the cross-endpoint kind:

```text
POST /profile        ->  writes display_name
GET  /admin/export   ->  reads display_name  ->  splices CSV/HTML/shell
```

```text
POST /invite   ->  creates pending membership row
POST /accept   ->  trusts that row
PATCH /role    ->  trusts the active state
GET  /admin    ->  trusts the role without re-authorization
```

When tracing an endpoint, do not stop at the request boundary. For
every security-relevant value or capability, ask:

- Where is it created or written?
- Where else is it read, trusted, transformed, or consumed?
- Does another endpoint observe it under a different authorization
  context?
- Does it persist through a database, cache, queue, file, token, or
  session?
- Can one endpoint create a state that another endpoint assumes was
  trusted?
- Can the output or capability of one path become the input or
  prerequisite of another?

Follow the relationship across files and endpoints until the
capability is consumed or the chain is disproved.

### Three flows

Track three relationships, not one:

```text
Value flow       request  -> parser -> service -> sink
State flow       endpoint A -> DB/cache/session -> endpoint B
Capability flow  bug A -> grants capability X -> endpoint B trusts X
                 -> consequence
```

The audit is most exposed on the second. A model that traces only
value flow will miss IDOR, business-logic, state-machine, and
cross-endpoint authz bugs.

### Reverse-consumer search

When the model meets any of the following, do not just ask who writes
it - ask who reads it, who trusts it, and under what authorization:

```text
resource ID     tenant ID        user ID
role / permission
token           session
database row    cache key
queue message   file path
webhook payload internal header
status / state enum
```

For example, on seeing `order.status = "approved"`, the next move is:

> Who reads `approved`? Which endpoints unlock behaviour after
> `approved`? Do all the write paths to `approved` carry the same
> authorization? Is the read path doing a fresh authorization, or
> just trusting the persisted status?

This is the most productive move for business-logic, IDOR,
state-machine, and cross-endpoint authz classes.

### One principle

> Every security-relevant write should trigger a search for its
> readers; every security-relevant read should trigger a search for
> its writers.

The Synthesize Hard Gate in `SKILL.md` instantiates this
principle at the audit-process level: any state-write /
state-consumer pair discovered by the reverse-consumer search
must be entered into the chain table or DISPROVED before
Report can start. This reference is the methodology; the Hard
Gate is the audit-side obligation that the methodology is
actually used.

## Read for what is missing

A code review that only reads present code finds present bugs.
Read for what is not there:

- Authorization. Every handler that touches a user-owned resource
  should have a permission check. A missing authorization check is
  a high-value hypothesis. It becomes a finding only after
  reachability and permission delta are established. Look for
  handlers whose sibling handlers check but this one does not.
- Validation. Every entry that feeds a sink should reject
  malformed input. Missing validation is a hypothesis, not a
  finding. It becomes a finding only when attacker-controlled
  input produces a meaningful permission or capability delta.
- Tests. A handler with no tests is a handler that has never
  been wrong from the test suite's perspective. That is evidence
  of low confidence, not evidence of safety.

## Read the git history when it matters

Recent changes, refactors, and reverted fixes are not noise — they
are the developer saying "I broke something here, and I either
fixed it or did not." For high-value targets, scan the last
six months of the file's history. Reverted fixes that did not
fully revert are a recurring pattern.

## When to stop reading and start writing

Stop Discovery when the audit notes file has, for every plausible
hypothesis the model can generate:

- A data path from an entry point to a sink.
- An explicit disproof condition.

If a hypothesis has neither, the audit is not ready to verify.