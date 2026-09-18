# SSRF

The application makes an HTTP (or any outbound) request whose
destination is partially attacker-controlled. The bug is not the
outbound request — it is what the attacker can reach via that
request that they could not reach directly.

## Where to look

- URL preview / unfurl handlers (chat, ticket, comment systems).
- Webhook configuration and test-trigger endpoints.
- File import / oEmbed / image proxy / PDF generator handlers.
- Outbound API integrations whose URL is partly attacker-supplied.
- XML external entity resolution (XXE → SSRF).
- DNS rebinding targets when the URL validator runs against a
  hostname and the application later resolves the IP itself.

## The interesting destinations

The destination matters more than the request:

- Cloud metadata services (`169.254.169.254`, `metadata.google.internal`,
  `169.254.170.2` for ECS).
- Internal admin panels on localhost / link-local / private
  networks.
- Redis, Memcached, Elasticsearch, internal databases on
  non-public ports.
- Other tenants' services when the cloud provides a flat
  internal network.
- Internal-only Kubernetes / Consul / etcd endpoints.

## Disproofs that often fail

- "We block private IPs." DNS rebinding bypasses IP checks that
  run only at validation time. The application must re-resolve
  at request time and re-check, or pin the resolved IP for the
  duration of the request.
- "We use an allowlist of hostnames." Hostnames resolve to
  attacker-controlled IPs. Allowlist of hostnames plus
  validation of the resolved IP, plus a re-check, is the only
  pattern that holds.
- "We only allow HTTPS." The protocol is not the question; the
  destination is.

## The permission delta

Read of cloud metadata → critical (full credential issuance).
Read of internal admin panel → high to critical. Reach to
internal-only database port → high. Reach to internal
infrastructure with a known exploit chain → critical.

A "blind" SSRF that only reaches a port with no exploitable
service is medium at most; it is not a finding without a
destination.