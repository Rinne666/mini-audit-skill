# Security Policy

## Supported versions

Only the latest released version receives security fixes.

## Reporting a vulnerability

Please report suspected security issues **privately**, either by email
to the maintainer address or through the project's **private
vulnerability reporting** flow.

**Please do not open a public issue.** A public issue is treated as a
disclosure, and the project may not process it.

Include, if possible:

- the affected component and version,
- the identity the attacker needs, in one sentence,
- the trust boundary that is crossed,
- reproduction steps from a clean state,
- the impact you observed.

Use only data you created yourself. If you can reach real user data,
say that it is reachable and stop there — do not download or publish it.

## What counts as a security issue

An issue is in scope when it lets a caller reach a resource or
capability that the caller's role does not permit, or when it lets an
unauthenticated caller act as an authenticated one.

The following are **not** security issues:

- behaviour that requires the operator to expose an uninitialised
  instance to an untrusted network;
- behaviour that requires a setting to be weakened from its documented
  default;
- issues in third-party components (report those upstream);
- issues that exist only in development or test tooling.

A configuration that the vendor ships or documents as a supported
deployment form is a default configuration, and issues that require it
are in scope.

## Credit

Reporters are credited in the release notes unless they ask not to be.
