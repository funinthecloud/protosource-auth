# 0002 — protosource-auth is an auth broker, not a partner-token vault

Status: ACCEPTED
Date: 2026-06-26
Context tags: v2 federation, access JWT (miy.6)

## Context

After the PKCE code-exchange at an external IdP's token endpoint, the callback
receives up to three artifacts from the partner:

1. an **ID token** — asserts "this principal is this person" (its `sub`, scoped
   by the partner `iss`, is the match key against our users),
2. a **partner access token** — usable to call the *partner's* APIs on the
   user's behalf, and
3. a **partner refresh token** — usable (with `offline_access`) to obtain more
   partner tokens.

When minting our own first-party session (shadow token + short access JWT), we
had to decide whether the shadow token should additionally retain the partner's
access/refresh tokens so the service could later act as the user *toward the
partner* (call Graph/Google APIs, or re-validate the partner session on each
refresh).

## Decision

protosource-auth is a **broker only**. The callback consumes the ID token to
extract `sub` (+ `email` via `claim_map`) and **discards the partner access and
refresh tokens**. Nothing partner-issued is persisted.

Concretely: `service/oauth.go` `HandleCallback` reads only `idToken.Subject` /
claims into a `FederatedIdentity`; the partner `*oauth2.Token`'s access/refresh
fields are never stored on the `Token` aggregate. Re-issuing *our* access JWT
(`POST /auth/refresh`) is gated solely on *our* state — shadow ISSUED +
unexpired, user `STATE_ACTIVE` (`Checker.Identify`) — and never calls back to
the partner.

## Rejected alternatives

- **Vault the partner access + refresh tokens on the `Token` aggregate
  (encrypted via the KeyProvider) so we can call partner APIs / honor upstream
  revocation.** Rejected: it would make protosource-auth a high-value breach
  target — a single store holding live, refreshable credentials to every
  federated user's partner accounts — and pull the service into the partner's
  API blast radius. The only thing it buys today is debugging convenience and a
  speculative "call the partner on the user's behalf" capability we have no
  use case for. The cost (a new encrypted-at-rest secret store + the standing
  liability of holding it) is not worth it. If a genuine "act as the user toward
  the partner" requirement appears, this is revisited as a deliberate, scoped
  addition (new `wrapped_partner_*` fields, KeyProvider-encrypted, same
  invariant as the issuer `client_secret`).

- **Keep the partner tokens only in process memory for the duration of the
  callback (don't persist, but use them once).** Rejected as out of scope: we
  have no in-callback partner API call to make. Extracting `sub` and dropping
  the rest is strictly simpler and leaks nothing.

## Consequences

- No `Token`-aggregate proto change: the shadow token stays a handle on *our*
  authenticated user + timing + revocation, exactly as in v1.
- Upstream (partner-side) revocation is **not** propagated mid-session: once we
  mint a shadow, our session lifetime is independent of the partner's until the
  shadow expires or is revoked locally. Acceptable for a broker; documented.
- Re-authentication (not refresh) is the path back to the partner — a fresh
  `/oauth/authorize` round-trip — if we ever need to re-assert the partner
  identity.
