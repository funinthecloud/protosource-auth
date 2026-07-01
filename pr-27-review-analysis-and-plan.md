# PR #27 Review Analysis & Action Plan

**Date:** 2026-07-01  
**Branch:** v2/discovery-stub (PR #27)  
**Reviews considered:**
- `pr-27-grok-review.md` (Grok reviewer subagent)
- `pr-27-copilot-review.md` (GitHub Copilot pull-request-reviewer[bot])
- Cross-reference: `PR_26_CODE_REVIEW.md` (prior similar feedback on audiences)

Both review files are staged in the working tree (`git add`).

## Executive Summary

This is a large, additive v2 feature PR (federated OIDC/PKCE IdP broker + short access JWTs as HttpOnly cookies + LinkedIdentity + JIT + admin forms). v1 credential paths remain untouched.

**Overall quality from both reviews:** High. Strong security hygiene (wrapped secrets, fail-closed sentinels, signed state cookies, distinct `token_use`, injectable time, good tests).

**Copilot** surfaced **2 focused issues** (both about stricter fail-closed after cryptographic success).

**Grok** surfaced **10 issues** (2 bugs, rest suggestions/nits), including the two areas of overlap with Copilot plus duplication, the long-standing `allowed_audiences` gap (also called out in the PR 26 review), pinned-issuer validation weakening, and polish.

**Real / important / addressable issues (consensus):** The items below. We recommend addressing the top 4 before or as part of merge; the rest can be tracked in beads or deferred.

## Consolidated Issues (validated against source)

### 1. State cookie: verifyState does not enforce presence of critical payload fields (Verifier, RedirectURI, IDP) — Copilot #1 + related to Grok #8

**Files:**
- `service/statecookie.go:119` (after unmarshal + expiry + state-nonce check)
- `service/oauth.go:320` (HandleCallback uses `claims.IDP`, `claims.Verifier`, `claims.RedirectURI` without re-check)
- Tests: `service/statecookie_test.go`

**Why real:**
- After successful signature verification, a claims object with empty critical fields can be returned.
- These fields drive IdP selection, PKCE code_verifier replay, and final redirect.
- Failure then surfaces downstream as "token_exchange_failed", "idp_unavailable", or weird redirect instead of clean `invalid_state`.
- Current early checks only cover jwt/expectedState + state-nonce + expiry.

**Suggestion (from reviews + analysis):**
Add after the existing `claims.State` check (and before `return &claims`):

```go
if claims.Verifier == "" || claims.RedirectURI == "" || claims.IDP == "" {
    return nil, errStateInvalid
}
```

Also consider a small upper-bound on the JWT header segment inside `jwtHeaderKid` (Grok nit).

**Priority:** High (auth flow integrity). Easy to implement + test. Add negative test cases.

**Status:** Address before merge.

---

### 2. Access JWT: VerifyAccessToken does not fail closed on empty iss/aud — Copilot #2

**Files:**
- `service/access.go:67` (after unmarshal)
- `service/login.go:370` (minter always populates `iss`, `aud`, `sub`, `token_use`, etc.)
- `authz/directauthz/directauthz.go:138` (Identify calls it with `a.accessAudience`)
- Tests: `service/access_test.go`

**Why real:**
- When `expectedAudience == ""`, the audience check is skipped entirely.
- No check that `claims.Issuer != ""` or `claims.Audience != ""` ever.
- The token is explicitly "for offline verification and audience scoping".
- Minuter guarantees non-empty values (falls back to issuer `iss`).

**Suggestion:**
After the `TokenUse` and `Subject` checks, add:

```go
if claims.Issuer == "" || claims.Audience == "" {
    return nil, ErrAccessTokenInvalid
}
```

Consider always requiring a non-empty audience in the claims (even if the caller didn't pass `expectedAudience`).

**Priority:** High (defense in depth for identity token). Low risk to change.

**Status:** ✅ **COMPLETED in parallel (Workstream 1)** — by isolated subagent. Added post-crypto checks for Verifier/RedirectURI/IDP + 4KB header guard in jwtHeaderKid + new `TestStateCookieMissingCriticalFields`. All state cookie tests pass under `-race`.

---

### 2. Access JWT: VerifyAccessToken does not fail closed on empty iss/aud — Copilot #2

**Files:**
- `service/access.go`
- `service/access_test.go`

**Why real:**
- When `expectedAudience == ""`, the audience check is skipped entirely.
- No check that `claims.Issuer != ""` or `claims.Audience != ""` ever.
- The token is explicitly "for offline verification and audience scoping".
- Minter guarantees non-empty values (falls back to issuer `iss`).

**Suggestion:**
After the `TokenUse` and `Subject` checks, add:

```go
if claims.Issuer == "" || claims.Audience == "" {
    return nil, ErrAccessTokenInvalid
}
```

Consider always requiring a non-empty audience in the claims (even if the caller didn't pass `expectedAudience`).

**Priority:** High (defense in depth for identity token). Low risk to change.

**Status:** ✅ **COMPLETED in parallel (Workstream 2)** — by isolated subagent. Added the presence checks for Issuer/Audience. Extended `TestVerifyAccessTokenRejections` with `empty_issuer` / `empty_audience` subtests using signed claims. All access-related tests (including roundtrips with `expectedAudience=""`) pass under `-race`.

---

### 3. allowed_audiences is stored, exposed in UI/proto, but never enforced — Grok #1 (also PR_26_CODE_REVIEW.md)

**Files:**
- `proto/auth/issuer/v1/issuer.proto:109`
- `service/oidcconfig.go`, `service/admin_issuer.go`
- `service/oauth.go:470` (`buildOIDCMeta` — only sets `ClientID`)
- `frontend/src/pages/IssuerOIDCForm.tsx`
- Generated code, V2 docs

**Why real (and known):**
- `oc.GetAllowedAudiences()` is round-tripped and accepted by admin form.
- `buildOIDCMeta` does:
  ```go
  cfg := &oidc.Config{ClientID: oc.GetClientId(), Now: h.now}
  ...
  verifier: provider.Verifier(cfg)  // or NewVerifier("", ..., cfg) with SkipIssuerCheck
  ```
- go-oidc therefore only accepts `aud` containing the `client_id`.
- Extra audiences configured by admins have zero effect on ID token acceptance.

**Options (choose one):**
A. **Wire it** (recommended for completeness): In discovery path use `SkipClientIDCheck` + manual audience check against union(ClientID + AllowedAudiences). In pinned path similar after signature. Add test with non-default audience. (May require care with go-oidc Verifier behavior.)
B. **Explicitly future-only**: Document in proto + form + CLAUDE.md + decision docs that the field is accepted for forward compatibility but not yet enforced. Consider hiding/disabling in the admin UI for now or adding "(not yet enforced)" label. Remove or keep the storage.

**Priority:** High (correctness / don't mislead operators + stored config). Medium implementation effort.

**Status:** Decide + implement or document before merge. (Do not ship advertised-but-broken feature.)

---

### 4. Pinned-endpoint OIDC mode weakens issuer validation (SkipIssuerCheck + empty issuer) — Grok #3

**Files:**
- `service/oauth.go:519` (pinned path)
- `service/oidcconfig.go` + admin form (supports discovery_url vs pinned endpoints)
- Comment in code already says: "ponytail: acceptable for pinned deployments; tighten if an issuer field is added to OIDCConfig."

**Why real:**
- `oidc.NewVerifier("", keySet, cfg)` with `SkipIssuerCheck = true` means signature + exp + (client_id) aud only.
- A malicious or misconfigured JWKS + endpoints for a different issuer can succeed if aud/exp match.
- The code itself recommends `discovery_url` for full validation.

**Options:**
- Prefer / default to / require `discovery_url` for EXTERNAL issuers (config-time validation in the OIDCConfigurator or admin handler).
- If pinned must stay: add an explicit `issuer` string to OIDCConfig (parallel to the endpoints), store it, and pass it to `NewVerifier(issuer, ...)` (even with other skips if needed). Reject mismatched iss.
- Add test that a token with wrong `iss` is rejected in pinned mode.

**Priority:** High (authN correctness for federated logins using pinned mode).

**Status:** Address (at minimum, document the risk loudly + prefer discovery; ideally add the `issuer` field or enforce discovery).

---

### 5. Duplicated cookie / redirect / security helpers (Grok #2)

**Files:**
- `service/oauth.go:613` (requestIsSecure, reqHost, isAllowedRedirectURL, registrableDomain, parentCookieDomain)
- `loginpage/loginpage.go:233` (very similar reqHost, registrableDomain, isAllowedRedirect, parentDomain, + reqHeader, isSameOrigin, matchesRegistrableDomain, etc.)

**Why real (maintainability):**
- Same publicsuffix logic, same Host header handling, similar HTTPS + eTLD+1 rules.
- Risk of divergence on future changes (IPv6, ports, new SameSite, etc.).
- Already some small differences in implementation.

**Suggestion:**
Extract to a small internal package (`internal/httputil`, `internal/cookieutil`, or similar) with table-driven tests for the domain/cookie/redirect rules (localhost, IP, IPv6, co.uk, apex, subdomains, etc.).

At minimum: add a cross-package test that asserts behavioral equivalence on a corpus.

**Priority:** Medium. Not a correctness bug today.

**Status:** Good follow-up; can be done post-merge or in this PR if time.

---

### Other issues from Grok (lower priority / nits / docs)

6. **Synthetic federated email** (`userID@federated.invalid`) in JIT paths (`service/identity.go:318` for AUTO_NO_ROLES / DOMAIN_RULE when no email claim). Persisted to GSI. — Suggestion: document clearly; consider non-email marker in future.
7. **login JSON response** only ever returns shadow (not access cookie); browser flows do. Wording in PR description / docs can mislead. — Nit: clarify contracts.
8. **Ephemeral link index warning** only in logs at startup (`app/router.go`). — Suggestion: surface in discovery or admin.
9. **Minor style** — discarding `, ok` on `token.Extra("id_token")` (oauth.go:437). Similar patterns elsewhere.
10. **Manual proto clones** in oidcconfig.go — opportunity to centralize.
11. **Cookie domain tests** — add more table-driven coverage for edge cases (already mostly correct).
12. **jwtHeaderKid** lacks size bound before decode (Grok #8, low severity because fail-closed).

These are mostly polish or already-tracked follow-ups.

**Positives noted in Grok review (confirmed):**
- State binding + pre-exchange verification.
- Secrets only plaintext inside configurator + exchange.
- JIT races handled via deterministic IDs + ErrAlreadyCreated.
- Distinct access vs shadow (`token_use`).
- HTTPS / origin checks everywhere sensitive.
- Excellent test clock + http client injection.
- v1 paths untouched.
- Real go-oidc + RS256 mock tests.

## Recommended Action Plan (prioritized)

1. **Before merge (must-address or explicitly document):**
   - Fix #1 (state cookie required fields).
   - Fix #2 (access token iss/aud enforcement).
   - Decide and act on #3 (`allowed_audiences`): implement or mark future-only + update UI/proto/docs.
   - Decide and act on #4 (pinned issuer validation): require discovery_url where possible, or add `issuer` field + enforce, + test.
   - Add tests for the above failure modes.

2. **This PR or immediate follow-up:**
   - Improve `jwtHeaderKid` with a reasonable header segment size limit.
   - Clarify docs / PR description / CLAUDE around access JWT issuance scope (shadow JSON vs browser flows).
   - Consider a small cross-test or shared util for the duplicated domain logic (or just add the equivalence test).

3. **Track in beads / later:**
   - Extract cookie/redirect helpers (dupe reduction).
   - Synthetic email handling / GSI implications for federated users.
   - Surface federation link index health somewhere observable.
   - Any other nits.

4. **Verification steps for fixes:**
   - `go test ./... -race`
   - Targeted new tests for the state cookie empty-field cases and access empty-iss/aud.
   - Manual or test IdP with non-default audience (if implementing #3).
   - Confirm pinned vs discovery behavior.
   - Run the full browser + API flows if possible (mkcert local or similar).

## Files staged for this analysis

```
A  pr-27-copilot-review.md
A  pr-27-grok-review.md
A  pr-27-review-analysis-and-plan.md   (this file)
```

Next: `git commit` these review artifacts? Or keep as uncommitted working notes while addressing the code issues? Decide with team.

## References

- Grok review: `pr-27-grok-review.md`
- Copilot review: `pr-27-copilot-review.md`
- Prior similar finding: `PR_26_CODE_REVIEW.md`
- Key source: `service/{statecookie,access,oauth,login,identity,oidcconfig}.go`, `authz/directauthz/directauthz.go`, protos, frontend form.
- ADRs added in this PR: `docs/decisions/0001-*.md`, `0002-*.md`, `0003-*.md`

---

*Plan generated by comparing the two automated reviews against the actual changed source on the branch.*
