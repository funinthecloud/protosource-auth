# protosource-auth v2 Implementation Plan

**Status**: Active implementation. Prerequisite dep bump + initial prep complete. See "Resume Summary" below for multi-session / compaction use. Based on [V2_FEDERATION.md](./V2_FEDERATION.md) (drafted 2026-05-19) + full codebase exploration + work in 2026-06 sessions. All changes additive; v1 fully preserved.

## RESUME / COMPACTION SUMMARY (for context restoration across sessions)
**Mission (1 sentence)**: Move from credential IdP (v1: email+argon2 + Loginer + long shadow cookie) to federated OIDC/PKCE IdP broker + local-owned authz (roles/function grants + shadow for revocation + short access JWTs for identity). Local creds + `protosource-authmgr recover-admin` stay as break-glass. `/authz/check` and downstream authorizers remain the function grant gate.

**Key invariants**: Additive only. Existing `/login` (creds), `shadow` (default) cookie, Token.Issue path, bootstrap, mgr CLI, Role grants, function matcher, all continue to work. Commit OIDC endpoint shapes *now* (in discovery doc) even if handlers stub/404 initially.

**Completed (as of this session)**:
- Dependency updated to `github.com/funinthecloud/protosource v0.6.1` (was v0.5.0). `go mod tidy`, plugins installed at v0.6.1, `buf generate` (Go+TS) run. Full `go test -race ./...` + builds pass. Regenerated `gen/.../*.protosource.lambda.pb.go` files (note: v0.6.1 changed internal error helper signatures to take `request protosource.Request` first — our hand-written service/ handlers use their own jsonError paths, unaffected).
- Cookie name made configurable (`app.Config.ShadowCookieName`, env `PROTOSOURCE_AUTH_SHADOW_COOKIE_NAME`, default "shadow" for BC). Wired to loginpage, whoami, router, authorizers, tests. (First prep item per V2_FEDERATION sequencing.)
- Discovery doc stub implemented: service/discovery.go with OIDC-shaped JSON (exact shape from V2_FEDERATION.md), request-derived base URLs (Host + X-Forwarded-Proto) + cfg.IssuerIss/cookieName, always-registered, plus stub 404 handlers that commit /oauth/authorize|callback|token|userinfo|jwks|logout paths. Wired in app/router.go (unconditional, with svc + lp). Comments/docs in service/router.go (loginResponseJSON, CheckResponseJSON) and app/router.go updated.
- Plan doc + cross-refs created/updated. Todos tracked.
- Code exploration via jcodemunch (resolve_repo first, search_symbols/get_file_content/search_text for code; native read for .md).

**Current phase**: Prep / "land v1 with cookie-rename + discovery". Cookie + discovery stub done (URLs committed, JSON live); next is JWKS endpoint (reuse resolver.VerificationKey + PublicJWK) or Issuer proto extension.

**Next actions (pick in any session)**: 1. JWKS endpoint (reuse resolver.VerificationKey). 2. Proto changes for Issuer OIDCConfig (client_secret wrapped via KeyProvider) + User LinkedIdentity. See full phases below. (Discovery handler complete.)

**For compaction / new session**: Read this "RESUME SUMMARY" + "Prerequisites" + "Open Design Calls". Load todos via context. Key files now: `go.mod` (v0.6.1), `app/config.go` (ShadowCookieName + Normalize), `loginpage/loginpage.go` (cookieName), `service/whoami.go`, `app/router.go`, `service/discovery.go`, `service/router.go`, `V2_IMPLEMENTATION_PLAN.md`, `V2_FEDERATION.md`. Use `jcodemunch__get_session_snapshot` if MCP available for prior exploration. Run `make gen` / `go build ./...` / `go test -race ./...` after any regen or dep work. Avoid editing generated/ without regen.

**Risks noted**: v0.6.1+ gen changes (errorResponse signatures), client_secret encryption never in events, state cookie signing reuses KIND_SELF keys (short TTL), JIT races on User create, cookie domain for federated flows.

**Open design calls** (settle before heavy coding): See V2_FEDERATION.md "Open design decisions". Recs: N linked ids, per-IdP JIT (default REJECT), break-glass local creds only, full OIDC provider (not just broker).

**How to resume work**: Update this summary at end of session. Use todo_write for granular progress. When tests pass and additive, good.

## Prerequisites Completed (do these before V2 phases)
- [x] Bump protosource dep to v0.6.1 (this session). Includes tidy + full regen + test verification.
- [x] Cookie rename prep foundation (configurable name, default preserved, all wires + tests updated).
- [x] Discovery doc stub + committed OIDC endpoint paths (service/discovery.go + app/router.go wiring; JSON live with cfg + request-derived URLs; stubs + comments updated).
- [x] Materialized this plan doc for cross-session use.

## Goal and Core Principles
**Goal**: Shift from "full IdP with local argon2id creds" (v1) to "federated auth (PKCE/OIDC to Google/Entra/etc) + owned authorization (roles, function grants, /authz/check, shadow + short access JWTs)" (v2). Local creds + mgr CLI recover-admin remain as break-glass only.

**Core Principles (from design + code)**:
- Additive only. v1 flows (/login with email/pass, shadow cookie "shadow", Loginer, Checker, existing aggregates, bootstrap, recover-admin, admin UI) must continue working unchanged.
- Commit URL shapes early (even 404ing or stubbed) so downstreams and the OIDC discovery doc don't have to change later.
- Reuse heavily: Role grants unchanged, Token aggregate (new creation path only), Key/Resolver (VerificationKey already exists for JWKS), Issuer KIND_EXTERNAL (extend it), functions matcher, signers, keyproviders (for client_secret too).
- Sensitive material (client_secret on external issuers) encrypted via KeyProvider before persisting, like signing keys. Plaintext only in process memory (like LiveKey privates).
- Stateless where possible (signed cookies for PKCE state+verifier using our signing keys).
- Per-IdP JIT policy (default reject).
- 1 User : N linked identities (keyed "{issuer_id}:{subject}"), not 1:1.

**Goal**: Shift from "full IdP with local argon2id creds" (v1) to "federated auth (PKCE/OIDC to Google/Entra/etc) + owned authorization (roles, function grants, /authz/check, shadow + short access JWTs)" (v2). Local creds + mgr CLI recover-admin remain as break-glass only.

**Core Principles (from design + code)**:
- Additive only. v1 flows (/login with email/pass, shadow cookie "shadow", Loginer, Checker, existing aggregates, bootstrap, recover-admin, admin UI) must continue working unchanged.
- Commit URL shapes early (even 404ing or stubbed) so downstreams and the OIDC discovery doc don't have to change later.
- Reuse heavily: Role grants unchanged, Token aggregate (new creation path only), Key/Resolver (VerificationKey already exists for JWKS), Issuer KIND_EXTERNAL (extend it), functions matcher, signers, keyproviders (for client_secret too).
- Sensitive material (client_secret on external issuers) encrypted via KeyProvider before persisting, like signing keys. Plaintext only in process memory (like LiveKey privates).
- Stateless where possible (signed cookies for PKCE state+verifier using our signing keys).
- Per-IdP JIT policy (default reject).
- 1 User : N linked identities (keyed "{issuer_id}:{subject}"), not 1:1.

## Current State Snapshot (condensed)
See the "RESUME / COMPACTION SUMMARY" at top of this document for the session-restorable view (completed items, next actions, key files, risks). The detailed historical exploration from the initial planning session follows in subsequent sections for reference when needed. The v0.6.1 bump + cookie prep are now reflected in status and code.
  - `cmd/protosource-authmgr/`: Direct repo access for ensure-tables, bootstrap, recover-admin (creates timestamped recovery user/role + assigns *). Never touches keys.
  - Frontend (TSX + generated clients): Issuers list/detail (shows kind, jwksUrl, algorithm, etc). No create form visible in main pages (Issuers.tsx is query-only; creation via CLI/generated commands or bootstrap). User/Role have creates.
  - `service/admin_user.go` etc for privileged ops.

- **Docs / Other**:
  - TODO.md points at V2_FEDERATION.md for JWKS, OIDC discovery, refresh, federated auth.
  - Router comments and CheckResponseJSON docs already reference V2_FEDERATION.md and "JWKS + OIDC discovery work".
  - README describes v1 credential curl flow (note: example response includes "jwt" but current HandleLogin JSON does not).
  - No .well-known, no oauth routes, cookie still "shadow" (not renamed/configurable).
  - loginpage has good CSRF (Origin/Referer + registrableDomain via publicsuffix), open-redirect protection, HTTPS enforcement.

- **Gaps vs V2 design**:
  - No LinkedIdentity on User.
  - Issuer lacks OIDC client config + wrapped secret + jit policy.
  - No PKCE state cookie machinery, no /oauth/authorize|callback.
  - No JIT provisioning path.
  - No JWKS or discovery endpoints (stubs needed to commit shapes).
  - Cookie name hardcoded in 4+ places (loginpage, whoami, app/router, tests, httpauthz usage in direct).
  - Loginer tightly bound to creds (will stay for break-glass; new path for federated token minting).
  - User Create requires password_hash; federated users will have none (or optional).
  - Access JWT vs shadow separation not yet in responses/flows.
  - httpauthz doesn't do local JWT verify yet.
  - Frontend Issuer forms lack OIDC fields.
  - "cookie-rename + discovery doc" arc (per V2 sequencing step 1) not fully landed yet.

**Related indexed repo**: funinthecloud/protosource (framework) — changes to aggregates require buf generate + protosource plugin compatibility. Regenerate affects gen/ and frontend/src/gen/.

## Recommended Sequencing (refined from V2_FEDERATION.md + code)

Follow the doc's 1-7, but front-load safe additive prep that doesn't touch aggregates (so we can ship "v1 complete" while v2 bakes). Land cookie config + committed discovery URLs + JWKS first — these are pure additions, zero impact on existing /login or shadow flows.

1. **Prep (land "v1 with cookie-rename + discovery")** — this doc + small code changes.
   - Configurable cookie name (default "shadow").
   - Stub (or real) discovery doc + JWKS endpoints registered with OIDC-shaped paths. Return the example JSON shape, with real values where possible (issuer, cookie_name, jwks_uri pointing at impl).
   - Update all "shadow" hardcodes + docs/README/CLAUDE.md.
   - This commits the contract so later PKCE work doesn't force consumer rewrites.

2. **Extend Issuer aggregate for KIND_EXTERNAL OIDC config** (proto change + regen).
   - New message OIDCConfig or fields: client_id, wrapped_client_secret, key_provider, master_key_ref, discovery_url (or the three endpoints), allowed_audiences (list), claim mappings (e.g. email_claim="email"), jit_policy (enum + domain for RULE).
   - New command(s): e.g. SetExternalConfig or extend Register (for creation of external). Events.
   - Pure data model + generated; the encryption of secret happens in a thin hand-written configurator (like Loginer does hashing).

3. **JWKS endpoint** (if not done in prep).
   - Real impl: for a given issuer (or default), load relevant Keys (state != EXPIRED, verify_until > now), return RFC 7517 JWKS with the public_jwk bytes (already in correct form per signer.Generate).
   - Wire into router always (additive).
   - Update resolver if needed for "list keys for issuer" (may need new query or scan via client; or add to Key aggregate GSI?).

4. **PKCE flow handlers + signed auth-request cookie**.
   - New `oauth/` package (or service/oauth.go) with handlers.
   - GET /oauth/authorize?idp=<issuer_id>&redirect_uri=...&... : validate idp is active KIND_EXTERNAL with OIDC config, generate verifier+state, build signed state-payload cookie (HttpOnly, short TTL, signed via resolver.SigningKey for our KIND_SELF issuer — reuse LiveKey or a helper), redirect to IdP authorize_endpoint with client_id, code_challenge=S256(verifier), state=..., scope=openid email profile, etc.
   - GET /oauth/callback?code=...&state=... : verify state cookie (parse as our signed JWT or custom, check exp/state match), load issuer config, decrypt client_secret (cache plaintext per-process like LiveKey), exchange at token_endpoint (POST, auth basic or post), verify ID token signature (use IdP's JWKS or pinned — we'll need an OIDC client helper or direct), extract sub + email_at_link per claim map, lookup or JIT User by (issuer_id, subject), mint shadow Token (via existing Issue path or thin wrapper) + short-lived access JWT, set shadow cookie (or return tokens), redirect to original redirect_uri with ?code=... or fragment per response_type.
   - Need: small OIDC discovery client or direct config use; PKCE helpers (challenge = base64url(sha256(verifier))); signed cookie helper (new or reuse signer for claims JWT with custom claims for verifier/redirect/exp).

5. **User linked_identities + JIT**.
   - Proto change for User (add message + map on aggregate; new collection events/commands? or internal apply from oauth handler).
   - New directory lookup? (FindByLinkedIdentity or extend UserDirectory).
   - JIT in callback: per issuer.jit_policy — reject (error), auto (create User with no password_hash + link + maybe default role), domain_rule (if email domain matches, grant a configured role_id).
   - Commands like LinkIdentity (for admin/manual) + Unlink. Events add to collection.
   - Update User Create to allow empty password_hash (for federated-only users). Existing local users keep hash.
   - Update whoami / check / admin to handle users without email or with multiple links (display primary?).

6. **Access JWT delivery + separation**.
   - On successful callback (and keep for break-glass /login if wanted): issue short access JWT (different TTL, perhaps different aud or claims, signed by our key) in addition to the long shadow Token.
   - Perhaps store both, or the access is ephemeral (not in Token aggregate? or add access_jwt to Token? Design says shadow is the persistent one).
   - New response on callback (and evolve /login JSON?): include access_token, id_token?, expires_in, plus set shadow cookie.
   - Update CheckResponse? or keep /authz/check for function grants only.
   - Downstream httpauthz learns "prefer Bearer access token for identity (verify locally via JWKS if possible); still use shadow/cookie for full /authz/check when function required".
   - Revocation: access JWTs have short TTL (5-15m); shadow for instant revoke.

7. **Docs, UI, polish, reposition Loginer**.
   - Update all docs to position local creds as break-glass.
   - Frontend: Issuer forms for OIDC config (client_secret input is write-only; display "configured" badge). Perhaps list linked identities on UserDetail.
   - loginpage: evolve to support "or sign in with..." buttons (links to /oauth/authorize?idp=xx) while keeping the email/pass form for breakglass. Or serve a picker.
   - Add /oauth/logout (clear cookie, optional backchannel to IdP).
   - Tests: lots of new (pkce happy path, state tampering, JIT variants, secret encrypt/decrypt, multi-IdP, access JWT verify).
   - mgr: perhaps add commands to register external issuer (with secret from env or prompt?).
   - Update CLAUDE.md, README examples (add federated curl/PKCE notes; keep v1 examples working).
   - Mark V2_FEDERATION.md as "in progress".

**Out of scope (per doc)**: token exchange RFC8693, SCIM, IdP group sync (roles stay local), step-up/MFA assertions, advanced refresh rotation.

## Detailed Task Breakdown (with code touchpoints)

(See the attached todo list in session for live tracking. Below expands with specifics.)

### Phase 0 / Prep (do first — minimal risk, high value for contract)
- [ ] Add to app/config.go: `ShadowCookieName string` + Env var `PROTOSOURCE_AUTH_SHADOW_COOKIE_NAME` (default "shadow"). Normalize sets default.
- [ ] Thread cfg.ShadowCookieName (or a resolved name) into:
  - loginpage.New + Page struct + handleLogin (c.Name = name) + tests.
  - service/whoami.go (cookieValue(req, name)).
  - app/router.go: buildAuthorizer(..., cookieName) → directauthz.WithTokenSource(httpauthz.Cookie(name)).
  - Update directauthz/httpauthz defaults/tests that hardcode "shadow".
  - authz tests, loginpage_test, service_test, app_test that assert cookies or use direct with cookie.
- [x] Add discovery handler (new file service/discovery.go):
  - Register GET /.well-known/openid-configuration (and /oauth/.well-known alias).
  - Return JSON matching the exact shape in V2_FEDERATION.md (issuer from cfg.IssuerIss, other endpoints as full URLs derived from request Host + X-Forwarded-Proto for scheme/host, cookie_name from cfg.ShadowCookieName, standard response_types etc.). Stub 404/not_implemented handlers for /oauth/authorize, /callback, /token, /userinfo, /jwks, /logout so the paths are explicitly committed in the router today.
  - Always registered (additive, no auth, no backend clients — public metadata). Wired unconditionally in app/router.go alongside svc + loginpage.
  - Commit the paths (per V2_FEDERATION "land v1 with ... discovery"): the oauth ones above + existing /authz/check.
- [ ] Real JWKS (can do in same prep or right after):
  - New handler in service or keys/: uses resolver to list keys for issuer (may need KeyClient query or add helper; for now load via known kids or extend resolver with ListVerificationKeysForIssuer).
  - Endpoint GET /oauth/jwks?issuer=... or /jwks (per discovery). Output {keys: [ {kty, use:"sig", kid, alg, ... from the public_jwk json + extras} ] }.
  - Note: public_jwk is already bytes of the JWK object from signer.
- [x] Update router.go comments, CheckResponseJSON docs, LoginResponse docs to reflect new reality (service/router.go loginResponseJSON + CheckResponseJSON godoc; app/router.go NewRouter minimal-set comment). Discovery now lands the committed OIDC contract; access JWTs + JWKS are the follow-on.
- [ ] Update README.md curl examples + description to note v1 vs upcoming federated. Add section "Federation (v2)" with pointer to the plan.
- [ ] Update TODO.md: move JWKS/OIDC items under v2 or mark as started.
- [ ] Update V2_FEDERATION.md status + add "Implementation notes" link or section.
- [ ] Add cfg for base public URL or derive from Host for discovery URLs (or require PROTOSOURCE_AUTH_PUBLIC_BASE or similar for accurate links in discovery).

**Verification**: Existing tests pass with default "shadow". New discovery returns valid JSON. curl to /.well-known/... works on fresh run. Cookie name changeable via env, affects set-cookie + whoami + authorizer.

### Phase 1: Issuer OIDC Extension (aggregate work)
- Edit `proto/auth/issuer/v1/issuer.proto`:
  - Add message OIDCConfig { string client_id=1; bytes wrapped_client_secret=2; string client_secret_key_provider=3; string client_secret_master_key_ref=4; string discovery_url=5; string authorization_endpoint=6; ... (pinned or discovery); repeated string allowed_audiences=...; map<string,string> claim_map=... (e.g. "email_at_link" -> "email"); OIDCJITPolicy jit=... ; string jit_default_role_id=...; string jit_domain=...; }
  - Add OIDCConfig oidc = N; to Issuer message (only populated for KIND_EXTERNAL).
  - Add enum OIDCJITPolicy { JIT_REJECT=0; JIT_AUTO_NO_ROLES=1; JIT_DOMAIN_RULE=2; }
  - New commands: SetOIDCConfig (or RegisterExternal), UpdateOIDCConfig, ClearOIDCConfig. Produce events.
  - Update Register to accept initial oidc for external? Or separate.
- Run `buf generate` (after clang-format on proto).
- Regenerated code in gen/auth/issuer/v1/ will have the new fields + client methods.
- Add hand-written support: new `service/oidcconfig.go` or similar with a Configurator that takes plaintext secret, does provider.Encrypt, builds the Set cmd with wrapped. (Needs access to KeyProvider + masterRef, like resolver setup.)
- Update bootstrap/RegisterDefaultIssuer (no change, still SELF).
- Update mgr CLI? Add support for registering external issuers with secrets (read from env or flag, but carefully — never log secret).
- Update frontend: extend IssuerDetail + (add create form if missing) with fields for OIDC (secret input type=password, never echo back; show "Client secret configured" if wrapped != nil).
- Tests: roundtrip external issuer with secret, decrypt works, only KIND_EXTERNAL can have it.

**Risk**: Proto change requires regen + any direct struct usage updated. Since additive fields, old snapshots ok?

### Phase 2: User Linked + JIT (aggregate + orchestration)
- Similar for user.proto: message LinkedIdentity { string issuer_id=1; string subject=2; string email_at_link=3; int64 linked_at=4; }; map<string, LinkedIdentity> linked_identities = N; (key computed as issuer:subject).
- Collection events: IdentityLinked, IdentityUnlinked (use collection ADD/REMOVE like RoleGrant).
- New commands LinkIdentity, UnlinkIdentity (or internal only at first).
- Relax Create: make password_hash optional (or add a CreateFederated command that omits it).
- In User snapshot etc update.
- New or extended directory: support lookup by linked (for callback fast path before loading full user). GSI? Or since small, query or maintain in-memory map in some backends. For Dynamo use existing or new index pattern.
- JIT impl lives in the oauth callback handler (load issuer, policy, decide create + link + assign role if rule, then Issue token).
- Update Loginer? No — keep for breakglass. New FederatedLoginer or thin func that does the mint after identity resolved.
- Update whoami to perhaps surface linked identities (or not, for privacy).
- Tests for multi-link user, same user from google+entra, JIT create, domain rule, reject.

**Note on UserDirectory**: currently FindByEmail. For federated primary path we'll bypass email for identity keying.

### Phase 3: PKCE + OAuth Handlers + State Cookie
- New dir `oauth/` (parallel to loginpage/, service/): handlers, pkce.go, statecookie.go.
- State cookie: use a KIND_SELF issuer's key (cfg.IssuerID or dedicated "oauth-state" issuer?) to sign a JWT whose claims are { "ver": verifier, "ru": redirect_uri, "st": state, "iss": our_iss, "exp": now+5m }.
  - Helper: func SignAuthRequest(stateCookie string, claims AuthRequestClaims) or simply produce JWT and set as cookie value (name configurable or "oauth_state").
  - On callback: extract cookie, verify via resolver.VerificationKey(kid from jwt header), unmarshal claims, match state param, use verifier for token exchange. Clear cookie (MaxAge=-1).
- Need small http client for IdP token exchange + JWKS fetch for ID token verify (or use our signers if we fetch the JWK).
- For ID token verify: the external issuer will have jwks_url or discovery; we can implement a simple verifier or reuse protosource patterns.
- Mint: after successful exchange + user resolution/JIT → use existing tokenRepo.Apply( &tokenv1.Issue{...} ) and also sign a short access JWT (different TTL, perhaps "azp" or scope claims, sub=user, iss=our).
  - Return both in a callback response (if not redirecting), and always set the shadow cookie for the session.
- Endpoints registered in NewRouter (additive).
- Support multiple IdPs: the ?idp= selects which external Issuer to use for the federation.

**State cookie signing issuer**: reuse the default KIND_SELF, or require one marked for "state signing". Simple: always use cfg's default issuer's current key for state cookies (short lived anyway).

### Later Phases
- Access token delivery + httpauthz evolution (add local verify path using JWKS; only call check for functions. Perhaps a new Authorizer mode or separate IdentityProvider + Authorizer).
- Loginpage evolution + frontend for IdP picker.
- Full tests, mgr support, docs, e2e with real Google/Entra (use test accounts).
- Update directauthz/httpauthz to optionally skip check if a fresh-enough access JWT (verifiable) is present and only identity is needed (downstream services opt-in via new ctx or handler options?).

## Risks & Mitigations
- **Proto evolution on live stores**: Additive fields + new collection types are generally safe in protosource (old events replay). Test replay on existing bootstrap data.
- **Secret handling**: client_secret plaintext must never be in events, logs, or returned by getters. Enforce in configurator + never put raw secret in any response. Frontend must not echo.
- **Replay / race in JIT**: Use deterministic user id? Or (issuer,subject) lookup first; on create tolerate ErrAlreadyCreated and link if missing. Key user by stable sub.
- **IdP clock skew / discovery caching**: Cache OIDC metadata / JWKS per issuer with TTL.
- **Cookie domain for oauth flows**: Same parentDomain logic must apply to state cookies.
- **HTTPS for PKCE**: Authorize/callback can be relaxed? But loginpage requires https; discovery should advertise https endpoints.
- **Multi-algorithm / RS256**: Deferred, but discovery already advertises support per doc.
- **Token exchange / refresh**: Out of v2 per doc. Shadow TTL is the session lifetime.

## Verification Gates (per phase)
- go test ./... -race passes (full suite + new tests).
- Manual: local run with bootstrap (v1 path still works: POST /login, set shadow, /authz/check, /whoami, admin SPA).
- New: configure a test KIND_EXTERNAL (mock IdP or real with test client), hit /oauth/authorize, simulate callback, observe User created with link, shadow set, access JWT returned/usable.
- Discovery + JWKS return correct shapes and verify with resolver.
- Cross-origin cookie still works (eTLD+1).
- mgr recover-admin + bootstrap untouched.
- No secrets in `protosource-authmgr` paths.

## Open Design Calls to Settle Before Heavy Impl
(See V2_FEDERATION.md "Open design decisions" — the recs are N linked, per-IdP policy, break-glass only, provider not just broker.)
- Exact path shapes (/oauth/callback vs /oauth2/... ?). Doc has /oauth/* — stick to it.
- How short access JWT claims differ from the long one in Token.jwt (aud? scope? azp?).
- Where to persist access JWTs (or are they fire-and-forget, not in Token aggregate? Token stays for the shadow revocation story).
- Claim mapping defaults (standard OIDC sub, email, etc).
- Whether /oauth/token endpoint for direct code exchange (for non-browser clients) or only the redirect flow for now.
- State cookie name (configurable? "oauth_state" or per-IdP?).

## Next Actions (for this session / immediate)
1. Land the cookie config + discovery doc stub + JWKS (prep phase) — this is the "real shift" on-ramp and matches the "land v1 with ... discovery doc" requirement.
2. Update V2_FEDERATION.md status and this plan with decisions.
3. Proto changes for Issuer (step 2) once prep is reviewable.
4. Use `go test -race ./...` and manual runs after each slice.
5. Coordinate with protosource if plugin changes needed for new collection types on User.

**References**:
- V2_FEDERATION.md (full design + example discovery JSON + open decisions).
- Current hardcodes: loginpage/loginpage.go:118 (cookie), whoami.go:42, app/router.go:40, service/router.go comments.
- Ready pieces: keys/resolver.go:VerificationKey, LiveKey, ComputeKid; service/check + login orchestration; publicsuffix logic in loginpage.

This plan is living — update as we implement and discover.

---
*Generated during planning session. Use the session todo list for granular progress.*
