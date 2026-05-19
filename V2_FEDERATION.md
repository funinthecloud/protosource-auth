# protosource-auth v2: federated authentication, owned authorization

Status: design notes, not yet committed work. Drafted 2026-05-19 alongside
the Azure deploy of v1.

## Mission shift

v1 is a full identity provider: User aggregate owns argon2id credentials,
Loginer mints a shadow token after verifying email + password.

v2 moves protosource-auth out of the authentication business and keeps it
firmly in the authorization business. External IdPs (Google, Entra ID,
others) authenticate users via PKCE; protosource-auth maps the federated
identity to a local User aggregate and owns the role grants that drive
`/authz/check`. We become the authorization plane; somebody else handles
MFA, password reset, account recovery, abuse mitigation, compliance.

Local credentials survive as a *break-glass* path (bootstrap admin,
mgr-CLI `recover-admin`) — not the primary login surface.

## Driver

We want PKCE integrations with Google, Entra ID, and other OIDC providers
as authentication sources, with role grants attached to the resulting
local identity. Building IdP-grade auth ourselves is a tar pit; federating
to providers who already solved it is the right call.

## What stays the same

- **Role aggregate.** Function-string grants are orthogonal to how
  identity is established.
- **Token aggregate.** Still the shadow → user mapping. Only the creation
  path changes (after PKCE callback succeeds instead of after Loginer
  verifies a password).
- **Function-string matcher** (`functions/match.go`).
- **`/authz/check` and downstream `httpauthz` / `directauthz`.** These do
  not care how the user logged in.
- **Issuer aggregate's KIND_EXTERNAL.** Already exists for verify-only
  issuers; that's exactly the slot external IdP signing metadata lives in.
- **Key aggregate + signing path.** We need this *more* — we will be
  issuing our own JWTs to downstream apps.

## What changes

### User aggregate

Credentials become optional, not central. Add a linked-identity
collection:

```
message LinkedIdentity {
  string issuer_id      = 1;  // local Issuer aggregate id (KIND_EXTERNAL)
  string subject        = 2;  // IdP's stable `sub` claim
  string email_at_link  = 3;  // for display only — not the identity key
  google.protobuf.Timestamp linked_at = 4;
}

// On User:
map<string, LinkedIdentity> linked_identities = N;
// Key format: "{issuer_id}:{subject}"
```

A single User can have Google + Entra + local password — all resolving to
the same authz subject. Identity keying uses `(issuer_id, subject)`, never
email (Google's `sub` is stable; their `email` can change). Email is a
display attribute on the linked identity record.

### Issuer aggregate

Extend KIND_EXTERNAL with OIDC client config:

- `client_id`
- `client_secret` (encrypted via KeyProvider — same wrap path as signing
  keys)
- `discovery_url` *or* pinned `authorization_endpoint` / `token_endpoint`
  / `jwks_uri`
- `allowed_audiences`
- claim mappings (which IdP claim populates `email_at_link`, etc.)
- JIT provisioning policy (see below)

### Loginer

Demoted to the break-glass path. Kept intact for the bootstrap admin and
mgr-CLI `recover-admin` flow, plus any deployment that genuinely wants
local credentials. No code removal — just a positioning shift in the
docs.

## New primitives

### PKCE flow handlers

- `GET  /oauth/authorize?idp=<issuer_id>&redirect_uri=...` — generates
  PKCE verifier + state, persists them in a signed cookie (stateless,
  multi-replica-safe), redirects to the IdP's authorization endpoint
  with the PKCE challenge.
- `GET  /oauth/callback?code=...&state=...` — verifies state cookie,
  exchanges code for tokens at the IdP's token endpoint, verifies the ID
  token signature against the IdP's JWKS, JIT-provisions or looks up the
  User, mints a shadow + (optionally) an access JWT, redirects back to
  the originating app.

### Ephemeral auth-request store

Signed cookie carrying the PKCE verifier + state + intended
`redirect_uri`. Stateless, survives replica scale-out, expires in
minutes. Signed using the same key infrastructure that signs the access
JWTs.

### JIT provisioning policy

What happens when an unknown `(issuer_id, subject)` arrives at the
callback. Configured per Issuer:

- `JIT_AUTO_NO_ROLES` — create User with zero roles, admin must grant.
- `JIT_DOMAIN_RULE` — create with a default role if the IdP-asserted
  email matches a configured domain (`@drhayt.com → reader`).
- `JIT_REJECT` — refuse login, require pre-provisioning by an admin.

All three should be available; default `JIT_REJECT` (safe default —
explicit opt-in to auto-create).

### JWKS endpoint

`GET /oauth/jwks` (or `/.well-known/jwks.json`). Exposes the public side
of our Key aggregates so downstream apps can verify access JWTs locally
without a network hop to `/authz/check` on every request.

### OIDC discovery doc

The `.well-known/protosource-auth` doc from the cookie-rename arc
becomes (or grows into) an `openid-configuration`-flavored document:

```json
{
  "issuer":                 "https://auth.fitc.drhayt.com",
  "authorization_endpoint": "https://auth.fitc.drhayt.com/oauth/authorize",
  "token_endpoint":         "https://auth.fitc.drhayt.com/oauth/token",
  "userinfo_endpoint":      "https://auth.fitc.drhayt.com/oauth/userinfo",
  "jwks_uri":               "https://auth.fitc.drhayt.com/oauth/jwks",
  "end_session_endpoint":   "https://auth.fitc.drhayt.com/oauth/logout",
  "cookie_name":            "shadow_azure",
  "response_types_supported":          ["code"],
  "grant_types_supported":             ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported":  ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "id_token_signing_alg_values_supported": ["EdDSA", "RS256"]
}
```

Downstream apps that already speak OIDC can integrate with zero custom
code. Commit the URL shape **on v1** (even if some endpoints 404) so v2
doesn't have to rewire consumers.

## Access token resolution

v1 conflates session identity and authorization into the shadow cookie.
v2 cleanly separates them:

- **Refresh-equivalent:** the shadow cookie (HttpOnly, server-
  dereferenceable, supports immediate revocation).
- **Access token:** short-lived JWT (~5-15 min) signed by our Key
  aggregates, delivered as `Bearer` to downstream apps, verifiable
  locally via JWKS.

`/authz/check` becomes the function-grant authorization check, not an
identity check. Downstream apps that only need identity can skip it and
verify the JWT locally. The per-request fan-out to auth disappears for
the identity-only path; only function-grant checks still hit the auth
service.

Revocation latency for the access token is bounded by its TTL. Anything
needing instant revocation (the current v1 behavior) keeps using the
shadow path.

## Open design decisions

These shape the data model and are hard to unwind — settle them before
implementation.

1. **OIDC provider to downstream apps, or session-cookie broker only?**
   Recommendation: provider. Standard OIDC integration on the consumer
   side is a huge ergonomic win for roughly the same implementation
   effort.
2. **1 User : N linked external identities, or 1 external = 1 User?**
   Recommendation: N. The same human will federate from multiple
   directories over time and you do not want orphaned role grants when
   their primary IdP changes.
3. **JIT provisioning:** per-IdP policy as designed above (default
   reject), or one global policy? Recommendation: per-IdP. Different
   directories carry different trust.
4. **Local credentials:** break-glass only vs fully removed?
   Recommendation: break-glass only — the mgr-CLI `recover-admin` path
   depends on it, and you want a way in when Google is down.
5. **Multiple IdPs concurrently:** "one IdP per deployment" (simpler) vs
   "N IdPs registered, user picks at login" (real)? Recommendation: N.
   Designing for one and retrofitting N is more painful than designing
   for N from the start.

## Migration / sequencing

The v1 → v2 shift is **additive**. No existing primitive is removed.

1. **Land v1 with cookie-rename + discovery doc** (current arc). Ship
   the discovery doc with OIDC-shaped URLs committed but empty so v2
   doesn't re-wire consumers.
2. **Extend Issuer for KIND_EXTERNAL OIDC config.** Pure aggregate work.
3. **JWKS endpoint.** Trivial — read existing Key aggregates, expose
   public material.
4. **PKCE flow handlers + signed auth-request cookie.** New endpoints,
   no aggregate changes beyond step 2.
5. **User linked-identity collection + JIT provisioning.** Aggregate
   change.
6. **Access JWT delivery alongside shadow.** New response shape on the
   callback; downstream `httpauthz` learns to prefer Bearer when
   present.
7. **Document break-glass vs federated paths.** Reposition Loginer in
   the docs.

Local credentials, mgr CLI, function-grant check, role assignment, and
all of v1's operational surface keep working throughout.

## Out of scope for v2

- Token exchange (RFC 8693) between linked identities.
- SCIM provisioning. JIT provisioning + manual role assignment covers
  the v2 use case.
- Group / role sync from the IdP. Roles stay locally owned.
- Refresh token rotation beyond the existing shadow TTL semantics.
- Step-up auth, ACR claims, MFA assertions surfaced to downstream apps.
