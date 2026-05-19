# PRD-001: Federated Authorization Service (protosource-authz)

**Status:** Draft – initial structure and framing  
**Date:** 2026-05-19  
**Author:** Initial synthesis from existing protosource-auth codebase + V2_FEDERATION.md  
**Intended Repository:** New repo (working name: `protosource-authz`) – deliberately separate from the current `protosource-auth` credential-focused implementation.

---

## 1. Problem Statement

Modern engineering organizations do not want to operate their own identity provider. They have already solved MFA, password reset, account recovery, device management, abuse detection, and compliance inside Google Workspace, Microsoft Entra ID, or another corporate directory.

What they **still** need is a single place that:

- Maps those externally authenticated identities to **locally owned, auditable authorization decisions**.
- Enforces fine-grained function-grant authorization (`{proto_package}.{CommandName}` with wildcards) across many downstream services.
- Provides both immediate-revocation sessions (shadow tokens) **and** scalable offline identity (short-lived JWTs verifiable via JWKS).
- Works across the deployment realities the organization actually uses: Azure Container Apps + Cosmos, AWS Lambda + DynamoDB, and local development.

Existing solutions either:

- Force you to move all identity into their SaaS (losing local role ownership), or
- Require every downstream service to implement its own role evaluation against the IdP’s groups/scopes (high fan-out, weak audit, no central policy).

We need a **purpose-built authorization plane** that federates identity from the directories you already trust and owns the authorization policy you cannot afford to scatter.

---

## 2. Vision & Positioning

**protosource-authz** is the central authorization service for event-sourced, function-grant protected systems built on protosource.

- **Authentication** is delegated to external OIDC IdPs (Entra ID, Google, others) via standard PKCE flows.
- **Authorization** (role grants, function-string matching, revocation) is owned locally in event-sourced aggregates.
- The service issues two kinds of credentials:
  - **Shadow tokens** (opaque, HttpOnly, server-dereferenceable) for instant revocation and browser cookie flows.
  - **Access JWTs** (short-lived, signed by our Key aggregates) for high-scale, offline-verifiable identity.
- It is **multi-cloud by design** and **tofu-first** for the Azure path.

It is the spiritual successor to the authorization kernel inside the current `protosource-auth` repository, but with the identity story inverted: the directory is no longer the source of truth for roles.

**Tagline (working):**  
“Federated identity. Owned authorization. One place to check.”

---

## 3. Goals & Non-Goals

### Goals (MVP scope)

- Support at least Entra ID and Google as primary authentication sources via OIDC PKCE.
- Preserve all existing function-grant semantics and `/authz/check` behavior for downstream protosource services.
- Deliver both shadow-cookie and Bearer JWT paths so consumers can choose revocation latency vs. scale.
- Provide a standards-friendly OIDC discovery document so generic OIDC clients can integrate with minimal custom code.
- Support the three deployment targets that matter:
  1. Azure Container Apps + Cosmos DB + Key Vault (HSM-backed) via tofu modules (primary production target).
  2. AWS Lambda + DynamoDB + KMS (via existing SAM patterns).
  3. Local development (memory store + local key provider).
- Keep the `protosource-authmgr`-style offline operational CLI that works even when the HTTP service is unavailable.
- Make local credentials a supported but explicitly **break-glass** path (bootstrap, disaster recovery, `recover-admin`).

### Non-Goals (at least for v1 of this product)

- Being a general-purpose IdP (no new password storage as primary path).
- SCIM provisioning or directory sync.
- Group/role import from the IdP (roles remain locally authored).
- Token exchange (RFC 8693) between linked identities.
- Step-up authentication or ACR claims surfaced to applications.
- Hosting the admin SPA in the same binary (separate deployable is acceptable, but the PRD must address the admin experience).

---

## 4. Architectural DNA We Intend to Preserve

This product is **not** a rewrite from scratch. It inherits a proven architecture that received an A-grade review in May 2026. The following principles and boundaries are non-negotiable starting points:

### 4.1 Layering (from `.jcodemunch.jsonc` + ARCHITECTURE_REVIEW.md)

| Layer                | Responsibility                                      | What may change for federated world |
|----------------------|-----------------------------------------------------|-------------------------------------|
| core-domain          | `keys/`, `keyproviders/*`, `signers/*`, `functions/`, `credentials/` (break-glass only) | Credentials package becomes secondary |
| service-layer        | `Checker` (primary), new `FederatedLoginer` / `OIDC` orchestration | Major new code here |
| app-composition      | Wiring, backend selection, key provider dispatch, now also OIDC client config | Will grow but must stay the single composer |
| authz-adapters       | `httpauthz` + `directauthz` (TokenSource strategy) | Minimal change; may prefer Bearer JWT |
| presentation         | OIDC endpoints (`/oauth/*`), discovery, JWKS, optional minimal break-glass login page | This layer is largely new |
| entrypoints          | Thin mains + Lambda handler + mgr CLI               | New OIDC-aware entry points |
| generated            | Five (or six) aggregates via protosource            | User + Issuer will gain fields |

**Invariant:** `service/` may only depend on core-domain abstractions and narrow `*Repo` interfaces. Presentation never leaks into service.

### 4.2 Pluggability as a First Principle

Everything that has ever been pluggable stays pluggable and is extended, not replaced:

- `KeyProvider` interface (local, awskms, azurekeyvault, future gcpkms, ocivault)
- `Signer` interface (ed25519 today, RS256 planned)
- Storage backends (memory, DynamoDB, CosmosDB)
- `TokenSource` (AuthorizationHeader, Cookie, Chain)
- `Authorizer` contract (HTTP vs direct)

New for v2: per-Issuer OIDC client configuration (discovery URL or pinned endpoints, client credentials wrapped by the same KeyProvider, claim mappings, JIT policy).

### 4.3 Operational Resilience

- The mgr CLI (`protosource-authz-mgr`) must be able to bootstrap, recover admins, inspect state, and apply role grants **without** the HTTP service running.
- All caches remain per-process (no distributed cache requirement).
- Deterministic key materialization (`kid = "{issuer}:{date}:{alg}"` + `ErrAlreadyCreated` race fallback) is retained and extended for signing the PKCE state cookies and access JWTs.

### 4.4 Generated Aggregates + Tiny Hand-Written Kernel

We keep the protosource discipline:
- User, Role, Token, Issuer, Key (and potentially a new lightweight `AuthRequest` or `OIDCSession` aggregate for the ephemeral PKCE state) are generated.
- All cross-aggregate security logic (PKCE exchange, JIT provisioning, shadow + JWT minting, function-grant evaluation) lives in a small, auditable `service/` package.

---

## 5. Data Model Changes (Additive)

### 5.1 User Aggregate

`credentials` (password hash) become optional.

New collection:

```proto
message LinkedIdentity {
  string issuer_id      = 1; // references Issuer aggregate (KIND_EXTERNAL)
  string subject        = 2; // stable `sub` from the IdP
  string email_at_link  = 3; // display / JIT only; not the identity key
  int64  linked_at      = 4;
}

map<string, LinkedIdentity> linked_identities = N; // key = "{issuer_id}:{subject}"
```

Identity resolution key is **always** `(issuer_id, subject)`. Email is never used as a lookup key for federated identities.

A single User may have zero or more linked identities + (optionally) one local credential record for break-glass.

### 5.2 Issuer Aggregate (KIND_EXTERNAL extension)

For `KIND_EXTERNAL` issuers that are now OIDC providers, we add configuration fields (exact proto shape TBD after decision on claim mapping strategy):

- `client_id`
- `client_secret_wrapped` (encrypted via the active KeyProvider for this issuer’s keys)
- `discovery_url` (preferred) **or** explicit `authorization_endpoint`, `token_endpoint`, `jwks_uri`
- `allowed_audiences` (list)
- `claim_mappings` (which claim → `email_at_link`, future: display name, etc.)
- `jit_policy` (enum or message): `JIT_REJECT` (default), `JIT_AUTO_NO_ROLES`, `JIT_DOMAIN_RULE` + domain → default role map

`KIND_SELF` issuers remain exactly as today (we still sign our own access JWTs and the ephemeral PKCE state cookies).

### 5.3 Token Aggregate

Unchanged in shape. Creation path now includes “after successful OIDC callback + JIT or lookup”.

We will likely add a `token_type` or `purpose` discriminator (shadow session vs access JWT) or keep them as separate Token records. Decision required.

---

## 6. Functional Surfaces (New + Existing)

### 6.1 OIDC Provider Endpoints (new primary surface)

- `GET  /.well-known/openid-configuration` (discovery document)
- `GET  /oauth/authorize`
- `GET  /oauth/callback`
- `POST /oauth/token` (authorization_code + refresh_token grants)
- `GET  /oauth/userinfo`
- `GET  /oauth/jwks` (or `/.well-known/jwks.json`)
- `GET|POST /oauth/logout` (end session)

The discovery document must advertise the cookie name(s) in use so downstream applications know what to send.

### 6.2 Existing Surfaces That Must Continue to Work

- `POST /login` (break-glass only)
- `POST /authz/check`
- `GET /whoami`
- Admin CRUD on User/Role/Issuer/Key/Token via generated handlers (or a new dedicated admin API surface)

### 6.3 JWKS & Offline Verification

Downstream services that only need identity (not function-grant checks) should be able to verify our access JWTs locally using the JWKS endpoint and skip the per-request call to `/authz/check`.

---

## 7. Deployment & Packaging (First-Class Requirement)

This product is defined as much by **how it is stood up** as by what it does.

### 7.1 Primary Production Target: Azure

- **Compute:** Azure Container Apps (or Azure Functions custom handler if cold-start economics justify it later)
- **State:** Cosmos DB (NoSQL) via the existing cosmos-eventstore patterns
- **Secrets / Keys:** Azure Key Vault (Premium, HSM-backed RSA KEK for envelope or direct wrap of signing keys)
- **Delivery:** Tofu modules under `tofu/azure/` (and `tofu/azure-bootstrap/` for tfstate)
- **Networking:** Public endpoints + Managed Identity + RBAC for first release; private endpoints + VNet as a follow-up when compliance requires it.
- **Image:** Same Go binary as all other targets (`cmd/protosource-authz`)

The tofu modules are a **first-class deliverable**, not an afterthought.

### 7.2 Secondary Production Target: AWS

- Lambda (provided.al2023 / arm64) behind API Gateway
- DynamoDB (via existing dynamodbstore patterns)
- KMS (direct or envelope via the awskms provider)
- SAM template (or migration to tofu/aws if the team standardizes)

Parity with the current `protosource-auth` Lambda path is required.

### 7.3 Local Development

- Memory backend + local key provider (XChaCha20-Poly1305)
- `PROTOSOURCE_AUTHZ_LOCAL_MASTER_KEY` (or equivalent)
- Optional: Cosmos emulator + local Azure Key Vault emulator story for “Azure flavor” local dev
- Same binary or `go run ./cmd/protosource-authz`

### 7.4 Operational Tooling

- `protosource-authz-mgr` (or `protosource-authzctl`) – talks directly to the backing store.
  - `ensure-tables`
  - `bootstrap`
  - `recover-admin`
  - `inspect-user`, `grant-role`, etc.
- Must work before the service has ever run and when the service is completely down.

---

## 8. Remaining Hard Decisions (Require Explicit Ratification)

The following were left open in V2_FEDERATION.md or are new because of the deployment focus. They must be closed before detailed design or implementation begins.

1. **Product & Repo Naming**
   - Is the working name `protosource-authz` acceptable, or do we want a different market name (`shadow-authz`, `fitc-authz`, `provenance-authz`, etc.)?

2. **Admin Experience**
   - Do we ship a new React admin SPA in the same repo (or sibling repo) that understands linked identities, OIDC client registrations (with secret wrapping), and per-Issuer JIT policies?
   - Or is the initial admin surface purely the generated protosource CRUD + the mgr CLI?

3. **Token Model for Access JWTs**
   - Are access JWTs also represented as `Token` aggregates (with their own TTL), or are they purely derived at callback time with no server-side record except the shadow?
   - Impact on revocation, replay, and audit.

4. **Cookie Naming & Multi-IdP Reality**
   - One cookie name per deployment (`shadow_azure`) or a more sophisticated scheme when multiple IdPs are registered and a user can choose at the authorize step?
   - How does the discovery document express “the” cookie when N IdPs are active?

5. **Claim Mapping & JIT Policy Expressiveness**
   - How rich does the per-Issuer claim mapping need to be in v1? (simple string claim name vs. CEL/JQ expressions)
   - Is `JIT_DOMAIN_RULE` sufficient, or do we need arbitrary attribute → role predicates?

6. **Break-Glass Login Page**
   - Do we keep a minimal HTML login page for the local-credential path, or is all break-glass access expected to go through the mgr CLI or direct API?

7. **Refresh Token Semantics**
   - Does the OIDC `/token` endpoint support refresh tokens that can mint new shadow tokens (and optionally new access JWTs) without re-hitting the IdP?
   - Or do we treat the long-lived shadow as the only refresh mechanism for now?

8. **Scope of the First Release**
   - Which of the OIDC endpoints are strictly required for a useful v1? (Can we launch with authorize + callback + jwks + discovery and add token/userinfo later?)

---

## 9. Phasing (High-Level)

**Phase 0 – Foundation (this repo’s v1 completion)**
- Land cookie rename + stable `/.well-known/openid-configuration` skeleton in the current `protosource-auth` so consumers have committed URLs.
- Finish JWKS endpoint.

**Phase 1 – New Product Seed**
- New repository + this PRD ratified.
- Extend User + Issuer aggregates (additive).
- Core OIDC authorize/callback + state cookie signing + basic JIT.
- JWKS + discovery document for the new product.
- One primary IdP (Entra or Google) end-to-end on Azure via tofu.

**Phase 2 – Polish & Second Target**
- Second IdP, richer JIT/claim mapping.
- Access JWT delivery + downstream `httpauthz` Bearer preference.
- AWS Lambda parity (or explicit decision to deprecate it for this product).
- Admin UI or documented mgr-CLI-only admin path.

**Phase 3 – Hardening**
- Rate limiting on auth endpoints.
- Audit emission paths.
- Private networking options.
- Formal threat model + pen-test.

---

## 10. Success Metrics (Proposed)

- Time for a new downstream protosource service to obtain a verified user identity: < 1 day (OIDC client + one TokenSource wiring).
- Time for an operator to add a new Entra app registration + role grant for a pilot user: < 30 minutes (including JIT or pre-provisioning).
- p99 latency of `/authz/check` on cache hit remains < 10 ms (current bar).
- Cold-start penalty on Lambda/Container Apps for key materialization is measured and acceptable.
- All three deployment targets have passing “hello world” tofu / SAM / local scripts in the repo.

---

## Next Steps

1. Ratify (or replace) the working product name.
2. Close or time-box the eight hard decisions in Section 8.
3. Decide the minimal viable set of OIDC endpoints and token shapes for Phase 1.
4. Produce the detailed technical design for the PKCE flow + ephemeral state signing (separate ADR or section).
5. Stand up the new repository with this PRD as `design/prd-001.md` (or equivalent) and the initial tofu/azure skeleton copied/adapted from the current work.

---

## Memorialized for Next Conversation

This section captures the key open items and branching options discussed while creating the initial draft. These are recorded here so the next session can pick up exactly where we left off without re-deriving context.

### A. Foundational Positioning Decisions
- **New repo vs. evolution of current repo**: Current working assumption is a clean new repository (`protosource-authz` or similar) that treats the existing `protosource-auth` as the reference implementation of the reusable authorization kernel. Confirm or reverse this.
- **Product name**: Working title is `protosource-authz`. Shortlist of alternatives to consider:
  - `protosource-authz`
  - `shadow-authz`
  - `fitc-authz` / `provenance-authz`
  - Something more market-facing that doesn't carry the "protosource" prefix

### B. Hard Technical & Experience Decisions (from Section 8)
These eight items still need explicit answers before detailed design work:
1. Product & repo naming (see above)
2. Admin experience model (new SPA vs. generated CRUD + mgr CLI only)
3. Token model for access JWTs (first-class Token aggregate vs. purely derived)
4. Cookie strategy for N concurrent IdPs
5. Claim mapping & JIT policy expressiveness (simple vs. CEL/JQ)
6. Break-glass login page (keep minimal HTML form or mgr-CLI only)
7. Refresh token semantics on the OIDC `/token` endpoint
8. Minimal viable OIDC surface for Phase 1 launch

### C. Deployment & Delivery Philosophy
- How sacred is "tofu as the instrument" for the Azure path? Is the tofu module the primary way customers stand this up, or is it one supported option among docs + manual steps?
- Do we keep full parity with the AWS Lambda path from day one of the new product, or is Azure the only first-class production target initially (with AWS as "community / best-effort")?
- Should the new product’s tofu modules live in this new repo under `tofu/`, or should we contribute improved modules upstream into the protosource monorepo modules?

### D. Scope & Sequencing
- What is the thinnest possible Phase 1 that still delivers a compelling "federated Entra + owned roles" story?
- Should the current repo’s v1 completion work (cookie rename + discovery doc skeleton + JWKS) land before we create the new repo, or can those happen in parallel?

### E. Governance & Process
- Where will ADRs live for the detailed design work (in the new repo under `design/adr/` or `docs/adr/`)?
- Do we want to use the `grill-with-docs` or similar rigorous review process for the next major sections of this PRD?

### F. Relationship to Existing Codebase
- Which exact packages from the current repo are we comfortable importing / vendoring / forking as the starting point for the new product’s core kernel?
- How do we handle the generated aggregate definitions (User + Issuer changes) across two repositories during the transition period?

**Last captured state**: 2026-05-19, after initial PRD skeleton creation and before any deeper ratification or design sessions.

---

*End of PRD-001 draft.*

---

*This document is intentionally written to be the seed for a new codebase, not a patch series against the existing `protosource-auth` repository. The current repository’s authorization kernel is the foundation we stand on; its credential-centric surface and admin UI are the parts we are deliberately leaving behind as the primary experience.*

**End of initial draft.**