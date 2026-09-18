# Cross-Service Trust

A service trusts another service's request because the request
arrived over an internal network, came with an internal API key,
or carries a header the internal services know to honor. The bug
class is the gap between "I am sure this is service A" and "I
should actually trust service A on this request."

## Where to look

- Service-to-service headers honored by the receiving service
  without independent verification (`X-User-Id`, `X-Tenant-Id`,
  `X-Internal-Role`).
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