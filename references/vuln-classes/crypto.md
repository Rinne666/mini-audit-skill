# Crypto

Crypto bugs are the most over-diagnosed class in audits. Most
"crypto" findings are not crypto bugs — they are configuration
errors, randomness bugs, or authentication-bypass bugs mis-labeled
as crypto. This reference keeps the list narrow.

## Live bug classes

- **Authentication token forgery.** JWT signed with the public
  key as the HMAC secret (`alg: HS256` + `verify(publicKey)`),
  unsigned JWT (`alg: none`), or weak HMAC secret.
  Re-implemented JWT, SAML response, OAuth code verifier.
- **Password storage.** Plain-text, MD5, SHA-1, single-pass
  SHA-256, bcrypt cost below 10, custom hash function.
- **Randomness.** `Math.random`, `random()` seeded with time,
  `os.urandom` for non-secret randomness (not a bug — but
  non-`os.urandom` for secrets is).
- **TLS misuse.** Cert verification disabled (`verify=False`,
  `rejectUnauthorized: false`), self-signed cert accepted, hostname
  verification disabled.
- **Padding oracle / CBC bit-flipping.** Live in legacy code,
  rare in new code.
- **Hard-coded keys.** API keys in source, default secrets in
  config templates.

## Where to look

- JWT / OAuth / SAML / OIDC code paths.
- Password reset tokens, magic-link tokens, email verification
  tokens.
- File-encryption code whose key is in source or in a
  world-readable config.
- TLS configuration in HTTP clients and outbound integrations.

## Disproofs that often fail

- "We use HTTPS." HTTPS is a transport guarantee, not an
  authentication guarantee. The bug is rarely in the TLS layer.
- "The token is signed." With what key, with what algorithm,
  with what validation? Read the verifier, not the signer.
- "We use bcrypt." With what cost factor? With what per-user
  salt? On which version of bcrypt?
- "We don't see the key in source." Configuration that is
  checked into source is in source.

## The permission delta

Auth forgery / token bypass → critical. Password dump /
hash-disclosure → critical. TLS verification disabled →
medium (the attacker already had a man-in-the-middle position).
Hard-coded API key → severity depends on what the key unlocks.