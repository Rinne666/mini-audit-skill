# Cross-Service Trust

A component trusts an asserted identity because it arrived over an
internal network, came with an internal credential, or carries a
header, protocol field, or name that the component knows to honor.
The trust boundary can be between services or inside one daemon.
The bug class is the gap between "this value says the peer is X"
and "the consumer independently verified that X may assert it."

## Where to look

- Service-to-service headers honored by the receiving service
  without independent verification (`X-User-Id`, `X-Tenant-Id`,
  `X-Internal-Role`).
- Proxy identity protocols and forwarded headers (`PROXY` protocol,
  `X-Forwarded-For`, `Forwarded`) whose asserted source address is
  passed into host or network ACLs. Check who can connect and send
  the assertion, whether the daemon validates the proxy, and which
  address the ACL actually consumes.
- DNS-derived names and reverse-lookup fallbacks used for allow/deny
  decisions. Follow lookup failure values such as `UNKNOWN` through
  the ACL evaluator; determine whether an unresolved deny entry fails
  open or closed.
- Client addresses, hostnames, peer certificates, and authenticated
  principal fields that are parsed or rewritten before the policy
  decision. Enumerate all writers and all consumers of the identity
  value, including local protocol handlers.
- Internal API keys in shared config or environment variables
  that any compromised service can read.
- Webhooks received over a public endpoint whose signature
  scheme is missing, weak, or accepts replay.
- Mutual TLS between services whose CA bundles any internal
  service.
- JWTs issued by one service and consumed by another where the
  consuming service accepts `alg: none` or `alg: HS256` with
  the public key.
- Service mesh tokens whose audience is not validated by the
  receiver.

## The shape

Every cross-service trust bug has the same skeleton:

1. A header / token / network position is treated as identity
   without independent verification.
2. The attacker can produce the header / token / network
   position.
3. The receiving service acts on the identity.

The model that finds these is the one that asks, at every
incoming boundary, "what would happen if the request came from a
different tenant / an attacker / a compromised internal
service?" If the answer is "we'd honor the header anyway," the
audit found a candidate.

## Disproofs that often fail

- "The header is only set by the internal service." A
  compromised service or a misconfigured sidecar sets it on
  attacker-controlled requests.
- "The API key is only in our config." Any service that can read
  the config has the key. Any vulnerability in any of those
  services leaks the key.
- "We use mTLS." The CA bundle is the question. A flat
  internal CA trusts every internal service to authenticate as
  every other internal service.
- "We validate the token." With what audience, what scope, what
  expiry?

## The permission delta

The delta is the same as the authz delta, but the threat model
is different: the attacker is not a user, they are a
compromised service. Severity follows the cross-tenant or
cross-service impact, not the technical primitive.

## Audit-process link

The cross-service trust pattern (header writer x downstream
trust consumer) is one of the three mandatory pairings in
the Synthesize Hard Gate of `SKILL.md`. When the audit finds
an internal service setting a header or accepting an internal
credential, the cross-service pair must be entered into the
chain table or DISPROVED before Report can start.
