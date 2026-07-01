## Summary

This PR additively extends protosource-auth into a federated OIDC/PKCE IdP broker while preserving all v1 credential+shadow paths. It introduces OIDCConfig on KIND_EXTERNAL Issuers (with KeyProvider-wrapped client secrets), PKCE /oauth/authorize+callback using signed state cookies (via SELF issuer keys), ID-token verification (via go-oidc), LinkedIdentity + JIT provisioning on User (with deterministic IDs + ErrAlreadyCreated races), short-lived access JWTs delivered only as HttpOnly cookies, Identify paths in Checker/directauthz, admin UI forms, and discovery/JWKS updates. 

The implementation intent is correct and the dominant design (stateless signed state, fail-closed sentinels, secret never persisted plaintext, v1 isolation, shadow as revocation root, access for identity only) is sound. Security-sensitive areas (crypto, cookie scoping via publicsuffix, PKCE binding, JIT races, access vs shadow claim separation) are handled with care and injected test clocks. Dominant residual risk areas are an advertised-but-unenforced OIDCConfig field, duplicated cookie/redirect/HTTPS helpers across packages (divergence risk), and relaxed issuer validation in pinned-endpoint OIDC configs. Test coverage for the new flows (mock RS256 IdP, state tampering/expiry, JIT policies, secret roundtrips, access reject-shadow) is strong and uses -race-friendly patterns.

No critical correctness bugs were found that would allow auth bypass or secret leakage under normal operation; issues are mostly gaps, duplication, and follow-ups explicitly noted in the codebase itself.

## Issues

### Issue 1 -- Severity: bug
- File: proto/auth/issuer/v1/issuer.proto:468
- Description: OIDCConfig.allowed_audiences (and the corresponding UI/claim fields) is stored and round-tripped through SetOIDCConfig/Register but never read or applied at runtime. In service/oauth.go:buildOIDCMeta the oidc.Config passed to go-oidc only ever sets ClientID (and SkipIssuerCheck in pinned mode); the verifier therefore always enforces aud containing exactly the client_id. Extra audiences advertised in the admin form and proto have no effect.
- Suggestion: Either (a) document the field as "future" / not yet enforced in the proto and IssuerOIDCForm.tsx, or (b) wire it: on verifier construction set SkipClientIDCheck and perform an explicit audience check against the union of ClientId + AllowedAudiences (or pass SupportedAudiences if the library version supports it). Add a test case exercising a non-default audience.
- Status: open

### Issue 2 -- Severity: suggestion
- File: service/oauth.go:680
- Description: Cookie domain derivation (parentCookieDomain), registrableDomain, isAllowedRedirectURL, requestIsSecure, reqHost are duplicated (nearly identical) with loginpage/loginpage.go (parentDomain, registrableDomain, isAllowedRedirect, isSecure, reqHost, matchesRegistrableDomain). Both use publicsuffix.EffectiveTLDPlusOne. Future edits (IPv6, port handling, new SameSite rules) can diverge.
- Suggestion: Extract the shared helpers into an internal package (e.g. internal/cookieutil or similar) and have both loginpage and service import it. At minimum add a compile-time or test-time assertion that the two implementations agree on a corpus of hosts.
- Status: open

### Issue 3 -- Severity: bug
- File: service/oauth.go:532
- Description: In pinned-endpoint mode (OIDCConfig with no discovery_url) the code explicitly does `cfg.SkipIssuerCheck = true` and constructs `oidc.NewVerifier("", keySet, cfg)`. Only signature, exp, and aud (via ClientID) are checked. The comment acknowledges this weakens iss validation and recommends discovery_url. A misconfigured or attacker-controlled jwks_uri + endpoints can therefore succeed for tokens from a different issuer that still satisfies aud/exp.
- Suggestion: Require discovery_url for new EXTERNAL issuers in the configurator (or at least warn loudly). If pinned mode must be supported, add an explicit `issuer` field to OIDCConfig, store it, and pass it to NewVerifier instead of "". Add a test that a mismatched iss is rejected even in pinned mode.
- Status: open

### Issue 4 -- Severity: nit
- File: service/oauth.go:437
- Description: `rawID, _ := token.Extra("id_token").(string)` discards the comma-ok value. While the subsequent `if rawID == ""` catch is safe, a non-string value in Extra would silently become "". Minor style issue and could mask a protocol oddity from the IdP.
- Suggestion: `rawID, _ := ...; if rawID == "" { ... }` is fine, but consider `v, ok := ...; if !ok || v == ""`. (Also applies to similar patterns elsewhere.)
- Status: open

### Issue 5 -- Severity: suggestion
- File: service/identity.go:318
- Description: In provision() for JIT_AUTO_NO_ROLES and JIT_DOMAIN_RULE, when the IdP supplies no email (or claim_map misses), a synthetic `userID@federated.invalid` is used to satisfy Create's min_len=3. This is persisted in the User.email GSI1 index. No deduping or collision handling beyond the deterministic userID.
- Suggestion: Document the placeholder behavior explicitly. Consider using a non-email marker or making email optional in a future User aggregate revision if federated-only users become common. Ensure admin UI and mgr surface the synthetic email clearly.
- Status: open

### Issue 6 -- Severity: nit
- File: service/login.go:391
- Description: loginResponseJSON (and the HandleLogin path) only ever returns the shadow token. The PR summary states "updates to login to issue both"; browser paths (loginpage + oauth) do issue the companion access cookie, but the JSON credential /login does not (by design per comments). This is intentional isolation but the summary wording could mislead.
- Suggestion: Update PR description / CLAUDE.md / docs to clarify that only browser-mediated login (page + PKCE) and /auth/refresh deliver the access cookie today; the direct /login JSON contract remains shadow-only.
- Status: open

### Issue 7 -- Severity: suggestion
- File: app/router.go:92
- Description: When wiring for persistent backends a warning is logged that the link index (MapLinkDirectory) is ephemeral, affecting JIT_REJECT. The warning is only emitted at router construction time if UserClient != nil. No equivalent surfaced to operators via discovery or health.
- Suggestion: Consider also exposing a "federation_link_index": "ephemeral" (or similar) field in the discovery document or a new /whoami or admin endpoint so operators know the limitation without parsing logs.
- Status: open

### Issue 8 -- Severity: nit
- File: service/statecookie.go:109
- Description: jwtHeaderKid performs base64.RawURLEncoding.DecodeString + json.Unmarshal without any length or structure sanity checks before treating the header as trusted for kid lookup. A huge or malformed header JWT segment will just cause errStateInvalid (fail-closed), which is acceptable.
- Suggestion: Add an explicit upper bound (e.g. 2k or 4k) on the first segment before decode to make the failure mode faster/more obvious in logs.
- Status: open

### Issue 9 -- Severity: suggestion
- File: service/oidcconfig.go:158
- Description: When preserving the previous wrapped secret on an endpoint-only Set, the code does `append([]byte(nil), prev.GetWrappedClientSecret()...)`. Similar clones exist for audiences/claim maps. Correct, but the number of manual deep clones for proto messages suggests a helper (already partially present as protoCloneOIDCConfig) could be centralized.
- Suggestion: Consider a single `cloneOIDCConfigForCommand` helper to reduce copy-paste surface for future fields.
- Status: open

### Issue 10 -- Severity: nit
- File: loginpage/loginpage.go:304 (and symmetric in oauth.go)
- Description: parentDomain / parentCookieDomain return ".etld+1" (with leading dot) or "". The code then passes it directly to http.Cookie.Domain. This is correct for cross-subdomain scoping, but localhost and IP cases correctly become host-scoped. No handling for single-label public suffixes in unusual cases.
- Suggestion: No action required for correctness; add a table-driven test covering co.uk, localhost, IPv6, apex, and subdomains to lock the scoping contract.
- Status: open

(If no further material issues are present after full diff + source review.)

## Notes on positives (not issues)
- State cookie binds verifier + redirect_uri + nonce + idp; verified before any IdP token exchange.
- All secret material (client_secret) only ever plaintext inside the configurator + exchange; wrapped bytes go to aggregates.
- JIT races are correctly handled via deterministic fed- IDs + ErrAlreadyCreated tolerance + idempotent LinkIdentity/AssignRole.
- Access JWT carries distinct `token_use:"access"`; VerifyAccessToken and directauthz.Identify reject shadow JWTs.
- HTTPS + origin checks present on every path that can mint tokens or accept secrets.
- Extensive use of injectable clocks and http clients for deterministic tests.
- Error paths map to generic codes; no secret or distinguishing details leak to clients.
- v1 credential paths (/login JSON, password verify, old shadow issuance) untouched.
- Tests exercise real go-oidc verification with RS256 mock IdP.

## Verdict
The PR is high-quality, security-conscious additive work. The two real bugs (unenforced allowed_audiences; weakened pinned-iss validation) and the duplication are the main items that should be addressed or explicitly documented before merge. Everything else is polish or known follow-ups already tracked in beads. The core authentication and session integrity properties hold.