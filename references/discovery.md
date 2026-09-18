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

## Read for what is missing

A code review that only reads present code finds present bugs.
Read for what is not there:

- Authorization. Every handler that touches a user-owned resource
  should have a permission check. Missing checks are bugs. Look
  for handlers whose sibling handlers check but this one does
  not.
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