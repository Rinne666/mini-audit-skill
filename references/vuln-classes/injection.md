# Injection

Injection is the result of an untyped boundary: attacker-controlled
text reaches a context that interprets it as code or structure.
The class covers:

- SQL injection (typed string substitution that breaks out of the
  literal).
- NoSQL injection (typed operator injection: `$ne`, `$regex`,
  `$where`).
- Command injection (shell metacharacter pass-through).
- Template injection (server-side template evaluation from
  attacker-controlled input).
- Header injection (CRLF, host header, response splitting).
- LDAP / XPath / GraphQL injection when a similar untyped
  boundary exists.

## The shape is the same

Every injection variant has the same skeleton:

1. A typed boundary the application does not own (SQL parser,
   shell parser, template engine, JSON parser with operator
   evaluation).
2. Attacker-controlled input that reaches the boundary.
3. A failure to encode or reject the boundary's metacharacters
   at the boundary crossing.

The model that wins audits sees this skeleton and asks "where in
this application does untrusted text cross a typed boundary?"
That single question produces most findings.

## Disproofs that often fail

- "We use parameterized queries." Confirm the parameterization
  actually binds the value. Watch for string concatenation inside
  a parameterized call (`"...WHERE id = " + id`).
- "We use an ORM." ORMs often expose escape hatches (`raw()`,
  `extra()`, `RawSQL`). Look for them.
- "We validate the input." Validation is not encoding. A length
  check or regex does not prevent the attacker from passing
  `'` once the boundary is crossed.
- "It's only reachable from a privileged user." Authentication
  is not authorization, but if the privileged user is the only
  reachable attacker, the delta is small.

## The permission delta

Cross-tenant data write → critical. Cross-tenant data read →
high. Read of own data via a same-channel bypass → medium.
Self-only reflection (self-XSS that requires the attacker to
send themselves the link) → low.