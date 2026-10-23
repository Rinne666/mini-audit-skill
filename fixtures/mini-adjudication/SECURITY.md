# Security Policy — fixture service

> The upstream acceptance policy for the `mini-adjudication` fixture.
> The adjudication cites it as `stated` authority: the answers below come
> from this file, not from the adjudicator's own reading of the code.

## Reporting channels

Two channels are accepted. The project states no preference between them.

1. **Private advisory flow** — the project's advisory platform. Every
   published advisory for this service came through this flow.
2. **Security email** — the maintainer address listed in the repository.

Both are open. Pick **one**. Sending the same report to both is duplicate
intake and reads as spam.

## Scope

In scope: the authentication, administration and share paths of this
service, including the external authentication extension's answer shapes.

## Previously published advisories

| ID | Subject | Classification |
|---|---|---|
| ADV-0001 | An empty extension response was treated as an approval on the admin plane | Security fix |
| ADV-0002 | The first administrator could be registered on an uninitialized instance without authentication | Hardening |

## How classification works here

An empty response from the extension is a documented answer shape, not a
failure. The product says so in the extension interface itself: the
extension answers with the payload it wants stored, or an empty string
when it has no opinion.

A path that treats an empty answer as anything other than "no opinion"
violates a rule the product has already stated, in the same release, on
the same input. That is a security fix, not hardening — the difference
between ADV-0001 and ADV-0002 is exactly this: a declared invariant that
the code violates on one path is a security fix; a missing control that
the product never claimed to have is hardening.

A finding that depends on an operator misconfiguring the service is
usually hardening. A finding that depends on a value the deployment
supplies, and that no amount of source reading can settle, is not yet a
finding at all.
