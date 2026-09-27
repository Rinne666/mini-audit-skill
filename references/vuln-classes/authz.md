# Authz — Broken Access Control

Authorization bugs are not "missing a check." They are:

- **Vertical.** A lower-privilege user reaches a higher-privilege
  capability. Classic IDOR is one form; missing role-gating on an
  admin endpoint is another.
- **Horizontal.** A user at the same privilege level reaches another
  user's data. IDOR, tenant boundary leaks, missing resource scoping.
- **Contextual.** A user holds the right role but in the wrong
  context (signed URL reused across tenants, session from one
  workspace replayed in another).

## Where to look

- Every handler that reads or writes a user-owned resource. Look
  for the **resource lookup** (`:id`, `:slug`, foreign key) and
  check that the authorization decision binds to that resource,
  not to the authenticated principal alone.
- Every endpoint whose sibling endpoints check a role and this
  one does not. Often a single handler in a controller skipped
  the decorator.
- File-path and signed-URL patterns. A signed URL with no
  resource binding can be replayed across users.
- Mass assignment on user-controlled fields like `role`,
  `is_admin`, `tenant_id`, `owner_id`.
- Authentication-critical fields such as authentication mode,
  external identity mapping, password state, or SSO linkage. Trace
  their writers to login and account-recovery consumers; a field
  need not directly store a role to change who can log in as whom.
- Multiple APIs that reach the same resource update primitive.
  Compare field-level allowlists and authorization granularity on
  legacy, current, bulk, and administrative paths instead of
  treating each API as a separate resource operation.
- Parsed input types at the guard and at the write. JSON numbers,
  strings, booleans, nulls, form values, and ORM-coerced values can
  make an apparently correct membership or equality check inert.

## Disproofs that often fail

- "There is a middleware that does it." Read the middleware. Does
  it cover every route? Does it cover nested routers?
- "The user must be authenticated to reach this." Authentication
  is not authorization. They are different checks.
- "The function takes the user from the session." Is the
  resource lookup keyed by that user, or by a parameter? If by a
  parameter, the attacker can pass another user's id.
- "There is a protected-field list." Does it include every field
  that affects authentication, authorization, ownership, or tenant
  selection? Read the update path and evaluate the list against the
  actual input types.

## The permission delta

Before the bug: read-only of own data (or no access). After the
bug: read/write of any user's data, or any user's role. Severity
follows the scope: cross-tenant is critical, same-tenant
horizontal is high, vertical-from-anonymous is critical,
vertical-from-low-priv is high.
