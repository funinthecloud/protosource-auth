# 0003 — Deliver the short access JWT as an HttpOnly cookie, not a JS-readable Bearer

Status: ACCEPTED
Date: 2026-06-26
Context tags: v2 federation, access JWT (miy.6)

## Context

miy.6 adds a short-lived, offline-verifiable **access JWT** alongside the
long-lived shadow token. The shadow token's *embedded* JWT is deliberately never
returned to network callers (returning it would let a holder validate offline
and bypass revocation). The access JWT is the deliberate, short-TTL, JWKS-
verifiable exception: downstream resource servers verify it via `/oauth/jwks`
without a `/authz/check` round-trip.

The open question was how the access JWT reaches the caller. The federated
`/oauth/callback` is a 302 + cookie redirect (it cannot return a JSON body), and
the deployment topology is a first-party SPA where the API and resource servers
live under one registrable domain (`.drhayt.com`), with the shadow cookie
already scoped to the eTLD+1.

## Decision

Deliver the access JWT as an **HttpOnly, Secure, SameSite=Lax cookie**
(`<shadow>_access`), scoped to the eTLD+1, never exposed to JavaScript:

- `/oauth/callback` sets it alongside the shadow cookie (and clears the state
  cookie) using the protosource v0.8.0 `Response.Cookies []*http.Cookie` field.
- the login-page break-glass path sets the same companion cookie.
- `POST /auth/refresh` re-validates the live shadow cookie and mints a fresh
  access cookie, returning only `{"expires_in": N}` (the lifetime, never the
  token) so the SPA can schedule a silent refresh without reading the token.

Downstream resource servers under the same domain read the access cookie and
verify it offline via JWKS (`service.VerifyAccessToken` /
`directauthz.Authorizer.Identify`). The access JWT carries `token_use:"access"`
and a distinct `aud`, so it can never be confused with the shadow's internal
JWT. `/authz/check` + shadow remain the authoritative **function-grant** gate;
the access JWT only conveys *identity*.

## Rejected alternatives

- **Return the access JWT in a JSON body for the SPA to hold in memory and send
  as `Authorization: Bearer`.** Rejected for the primary (browser) path: a
  JS-readable token is exfiltratable by any XSS payload. HttpOnly removes that
  exfiltration vector entirely (JS cannot read the cookie). The trade-off —
  HttpOnly means JS cannot attach the token as a Bearer header, so downstream
  must consume it *as a cookie* — is acceptable here because every resource
  server shares the eTLD+1. (Programmatic / cross-domain / native clients that
  genuinely need a Bearer-in-body are a deferred follow-up; they are not
  served by a cookie and don't exist today.)

- **Append the access token to the callback redirect URL fragment
  (`#access_token=…`), implicit-flow style.** Rejected: this is the deprecated
  OAuth implicit pattern — the token lands in browser history and can leak via
  the `Referer` header and logs. The OAuth 2.0 for Browser-Based Apps BCP
  explicitly steers away from tokens-in-URL.

- **A non-HttpOnly access cookie the SPA reads and re-attaches as a Bearer.**
  Rejected: it combines the downsides of both (readable by XSS *and* cookie
  semantics) for no gain over the HttpOnly cookie.

## Consequences

- **CSRF obligation.** An auto-attached cookie means state-changing downstream
  calls need CSRF defense (SameSite=Lax + Origin/Referer checks — the same
  discipline `loginpage` already applies for the shadow cookie). This is the
  trade for removing the XSS-exfiltration vector. SameSite can be tightened to
  Strict per-deployment if the navigation flows allow it.
- **Reach.** A cookie only serves browser clients under the eTLD+1. Non-browser
  API clients / native apps / cross-domain services would need a Bearer-in-body
  delivery — filed as a follow-up, built only when such a consumer appears.
- **Revocation window.** The access JWT is ephemeral (default 10m TTL,
  `PROTOSOURCE_AUTH_ACCESS_TOKEN_TTL`); the TTL *is* its revocation window. The
  shadow token remains the instant-revoke handle — a revoked shadow stops
  `/auth/refresh` from minting new access cookies. See [0002] (broker-not-vault)
  for why the shadow, not a stored access-token record, is the revocation point.
- **Non-confusability** is enforced in code: `VerifyAccessToken` requires
  `token_use:"access"`, which the shadow's embedded JWT lacks, so the two JWT
  kinds cannot be substituted. (RFC 9068 `typ:"at+jwt"` header would add a
  second discriminator but needs a `signers` change — deferred follow-up.)
