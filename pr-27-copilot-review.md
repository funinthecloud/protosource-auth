# PR #27 - Copilot Review (pulled 2026-07-01)

**Bot:** copilot-pull-request-reviewer[bot] / Copilot  
**Review ID:** 4609450859  
**State:** COMMENTED  
**Submitted:** 2026-07-01T13:29:07Z  
**Files reviewed:** 72 of 75

## Copilot Overview (abridged)

This PR evolves protosource-auth from a v1 credentials IdP into a v2 federated OIDC/PKCE broker with locally-owned authorization...

Copilot reviewed the vast majority of new and modified files (service/*, protos, gen, frontend forms, docs/decisions/00*.md, loginpage updates, app wiring, .beads, AGENTS.md, CLAUDE.md, etc.).

## Copilot Issues (exact)

### 1. service/statecookie.go (review comment)
"verifyState accepts a successfully verified JWT even if required payload fields (verifier, redirect_uri, idp) are empty. Those values are later used to exchange the code and select the issuer; failing fast here makes the state-cookie contract stricter and avoids downstream errors being reported as token-exchange/idp failures rather than invalid_state."

**Location (approx):** after successful signature + expiry + state-nonce check in verifyState, before returning claims.

### 2. service/access.go (review comment)
"VerifyAccessToken currently allows tokens with empty iss/aud (when expectedAudience is empty). Since this JWT is meant for offline verification and audience scoping, failing closed on missing iss/aud avoids accepting malformed tokens and enforces the same invariants the minter sets."

**Location (approx):** in VerifyAccessToken after unmarshal, before or after the existing subject/expiry checks.

## Other notes from Copilot review body
- Extensive file table (new PKCE/state, identity/JIT, OIDC config, access JWT mint+verify+refresh, admin issuer forms, etc.).
- No other inline comments generated.

