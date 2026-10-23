# Advisory — empty-external-answer-rewrites-stored-password

> Fixture: the expected advisory for the one reportable finding in
> `fixtures/mini-triage`. It locks the disclosure form: invariant
> subject, explicit attacker identity, symmetric divergence, honest
> score, and no invented version range.

## Title

An empty external-auth response rewrites the stored password instead of
failing the authentication closed

## Affected component

- `AuthService::login` — the protocol-user login path.
  `fixtures/mini-triage/app.php:70`
- The branch that handles an empty extension answer.
  `fixtures/mini-triage/app.php:76`
- The extension is wired to the login path by the operator as a
  documented authentication extension.

## Attacker identity

An unauthenticated network client that knows only an existing username.

## Trust boundary crossed

From **L0 — anonymous client** to **L1 — authenticated as the target
user**: the attacker authenticates as an account whose credential it
does not hold, and thereby reaches that account's resources.

## Preconditions

- Attacker state: network reachability to the login endpoint, and the
  username of an existing account.
- System state: an external authentication extension is configured for
  password authentication. The operator configured a documented feature
  correctly; the extension answering with an empty body is a normal
  answer shape, not a misconfiguration by the operator.
- The target account already exists. An account with an empty stored
  hash takes the same branch.

## Same-version behaviour divergence

`AuthService::probe` refuses the same empty extension answer
(`fixtures/mini-triage/app.php:106`), and `AdminService::login` refuses
it as well (`fixtures/mini-triage/app.php:122`). Only
`AuthService::login` treats the empty answer as a request to set the
password (`fixtures/mini-triage/app.php:76`).

The product's own comment on that branch states the intended contract:
*"The extension had no opinion. The stored credential must survive
untouched, and the presented password must be checked against the
unchanged stored hash."* The branch does the opposite of what its own
comment says.

## Attack path

1. The attacker sends a login attempt for an existing username with a
   password of their choosing. `fixtures/mini-triage/app.php:70`
2. The extension answers with an empty body. The code compares the
   answer against the empty string and takes the rewrite branch.
   `fixtures/mini-triage/app.php:76`
3. The branch writes `password_hash($password)` over the account's
   stored hash, then returns true.
   `fixtures/mini-triage/app.php:82`
4. The stored credential is now derived from the value the
   unauthenticated client presented.

## Impact

The attacker authenticates as the target account, with a password the
attacker chose. The account's stored credential is replaced, so the
previous password no longer works and the account owner is locked out
until an administrator resets it.

## Evidence

- The rewrite branch and its unconditional write.
  `fixtures/mini-triage/app.php:76`
- The probe refusing the same condition.
  `fixtures/mini-triage/app.php:106`
- The admin plane refusing the same condition.
  `fixtures/mini-triage/app.php:122`
- The negative control that would have disproved it: if the empty
  answer were handled as "no opinion" anywhere on this path, the
  presented password would be compared against the unchanged stored
  hash and the login would fail. Two sibling paths do exactly that,
  which is why this one is the defect.

## Severity

`high` — an unauthenticated client takes over any existing account,
replacing its credential and locking out the owner.

**CVSS v3.1**: `CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` →
**7.4 (High)**.

- `AC:H` because the configured extension must answer with an empty
  body for the targeted login attempt.
- `A:N` because the availability impact is confined to the affected
  account being locked out by the rewritten credential, which an
  administrator can reset; the confidentiality and integrity impact
  for that account is complete.

## Version and scope

- **Version tested**: the fixture target at its current revision.
- **Affected range**: every build that contains this function. The
  introducing commit was not traced, so no release boundary is
  asserted.
- **Patched version**: none released. The fix is not yet published.

## Why existing controls missed it

The product never enforces the invariant "a credential presented by an
unauthenticated client must never become the stored credential". The
probe and the admin plane implement that rule by refusing an empty
extension answer, but the protocol-user login path has no such check —
it treats the empty answer as an instruction instead of as an absence,
so the rule is enforced on two paths and not on the third.

## Suggested remediation

Treat an empty extension answer as "no opinion" on this path, exactly
as the probe and the admin plane do: read the stored hash, verify the
presented password against it, and fail with invalid credentials on a
mismatch. Do not write the presented password to the store on this
path. The smallest change is the branch condition at
`fixtures/mini-triage/app.php:76`; the same rule should be asserted
where the extension is invoked, so a future path cannot reintroduce it.

## Notes for the submitter

- Channel: the private advisory flow — the one the project publishes
  through. Email is reserved for a case where anonymity is required.
- Credit / attribution: to be settled with the submitter before
  submitting.
- AI-assistance disclosure: to be answered truthfully before
  submitting.
- **This Skill produces drafts and checks. It does not submit. The
  submit action requires the submitter's explicit confirmation.**
