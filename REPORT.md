# SecureShield — Brief Report

A short technical companion to the `SecureShield` RBAC API. Two topics,
roughly one page each, as required by the assignment brief.

---

## 1. Why salting is necessary to prevent rainbow-table attacks

A **rainbow table** is a precomputed mapping from candidate passwords to
their hashes. Given a leaked database of unsalted hashes, an attacker simply
looks each hash up in the table and recovers the original password in
milliseconds — no brute force needed at attack time, just storage and a
lookup. The economics favour the attacker because the table is built
**once**, offline, and reused against every victim database that uses the
same hash algorithm.

A **salt** is a random per-user value that is concatenated with the password
before hashing:

```
stored_hash = bcrypt(password || salt)
stored_row  = (salt, stored_hash)
```

Salting defeats rainbow tables for three reinforcing reasons:

1. **It explodes the table size.** Without a salt the attacker only needs
   one table per algorithm. With an *n*-bit salt they would need 2ⁿ tables —
   one per possible salt — to cover every hash. For bcrypt's 128-bit salt
   this is astronomically infeasible.
2. **It eliminates parallel cracking.** Even if 1,000 users in the leaked
   database all chose `password123`, every row stores a different hash
   because each row has a different salt. The attacker has to attack each
   user independently; cracking one row does not help with the next.
3. **It frustrates lookup-based attacks generally.** Salts turn the offline
   step (build a table) into an online step (rebuild a table for every salt
   you encounter), which converts a fast precomputation problem back into a
   slow brute-force problem.

`flask_bcrypt.generate_password_hash` does this automatically: it draws a
fresh 128-bit salt from the OS RNG, runs the password through bcrypt's
key-stretching loop, and stores salt and digest together in the standard
bcrypt string (`$2b$<cost>$<salt><hash>`). The cost factor (default 12) also
makes each guess expensive on purpose — bcrypt is deliberately slow so that
even a salted brute force at ~10⁵ attempts/second is unattractive, whereas
plain SHA-256 would do ~10⁹/second on a single GPU.

In `SecureShield`, every registration in `app.py` hashes the user's password
with this exact primitive (`bcrypt.generate_password_hash`), so two users who
happen to choose the same password still end up with completely different
rows in `users.db`. A rainbow-table attack against a hypothetical leak of
that database would therefore degenerate into a per-row brute force at
bcrypt cost — essentially the strongest defence the algorithm offers.

---

## 2. Risks of storing sensitive data inside a JWT payload

A JWT is **signed, not encrypted**. The default `HS256` token used in this
project is three Base64URL-encoded segments joined by dots:

```
<header>.<payload>.<signature>
```

The signature only proves *integrity* — that nobody changed the payload
after the server signed it. It says nothing about *confidentiality*. Any
party who holds the token can split it on `.`, Base64URL-decode the middle
segment, and read every claim in clear text. Tools like `jwt.io` do this
automatically. That single property drives most of the risk:

- **Trivial disclosure.** If a developer drops a password, session secret,
  national ID, or credit-card number into the payload, every intermediary
  that ever sees the token (browser history, error reports, proxy logs, CDN
  caches, mobile-app crash dumps) sees those secrets too. Tokens are
  routinely sent over HTTPS, but the whole supply chain that touches them
  is much wider than the TLS tunnel.

- **Long lifetime, large blast radius.** A leaked JWT is usable until it
  expires — and because JWTs are stateless, simply changing the database
  does not invalidate them. If the payload contains a password, the
  attacker keeps that password forever, not just until the current session
  ends.

- **No revocation guarantee.** Stateless JWTs cannot be unilaterally
  revoked without extra machinery. The blacklist in this project (Task 5)
  helps with the *token*, but it cannot un-leak a sensitive claim that was
  already inside that token.

- **Size and replay surface.** Bigger payloads mean bigger attack surface:
  every claim is shipped on every request. Sensitive data therefore ends
  up in many more places (web-server access logs, HTTP/2 frame dumps,
  observability traces) than a single login request would.

- **Mis-trusting the signature.** A common second-order mistake is treating
  the signed payload as authoritative server state. If the payload carries,
  for example, a balance, a permission level beyond `role`, or a list of
  feature flags, an attacker who steals the token freezes that state until
  expiry — even if the server-side row has since been suspended.

The defensive rule, which this project follows, is:

> **Put identifiers in the JWT, not secrets.** Use the payload only for
> claims the server can re-derive or re-validate (`sub`, `role`, `iat`,
> `exp`, `jti`). Anything genuinely sensitive stays server-side and is
> looked up by `sub` on each request.

In `SecureShield` the payload is exactly that minimum — username, role, and
the metadata required by the spec (`iat`, `exp`, `jti`). The password hash
never leaves the database; the secret key never leaves the server process.
A leaked token therefore exposes only the identity and role, both of which
the server already controls and can revoke via the blacklist.
