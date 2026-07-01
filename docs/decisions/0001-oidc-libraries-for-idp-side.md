# 0001 — Use coreos/go-oidc + x/oauth2 for the IdP side of federated login

Status: ACCEPTED
Date: 2026-06-26
Context tags: v2 federation, PKCE, Track A (miy.7)

## Context

Track A implements the federated-login authorization-code flow with PKCE
(`/oauth/authorize` + `/oauth/callback`). The callback must, against a *real*
external IdP (Google, Microsoft Entra, Okta, …):

1. discover the IdP's authorization/token/JWKS endpoints,
2. exchange an authorization code at the token endpoint (with the PKCE
   `code_verifier`), and
3. verify the returned **ID token's signature** against the IdP's JWKS,
   including key rotation/caching, and validate `iss`/`aud`/`exp`.

Our in-repo `signers` package only implements **EdDSA** (Ed25519, for signing
*our own* shadow JWTs). Real IdPs predominantly sign ID tokens with **RS256**
(Google, Entra) or ES256. So the IdP side needs JOSE capabilities our code does
not have, plus JWKS fetching/caching and the OIDC discovery protocol.

## Decision

Use two vetted libraries for the **IdP side only**:

- `github.com/coreos/go-oidc/v3/oidc` — discovery (`oidc.NewProvider`),
  JWKS-backed ID-token verification (`provider.Verifier` / `oidc.NewVerifier`
  + `oidc.NewRemoteKeySet`, which handles RS256/ES256/EdDSA and key caching),
  and claim extraction.
- `golang.org/x/oauth2` — building the authorization URL (`Config.AuthCodeURL`)
  and exchanging the code (`Config.Exchange` with `oauth2.VerifierOption` for
  PKCE).

Our **own** state cookie and minted shadow token continue to be signed/verified
with `keys.Resolver` (EdDSA). go-oidc/x-oauth2 never touch our signing keys.
The PKCE S256 verifier/challenge derivation is a few lines of stdlib in
`service/pkce.go` (so the verifier can live in our signed state cookie and be
unit-tested against the RFC 7636 vector); everything else IdP-facing is the
libraries.

## Rejected alternatives

- **Extend the in-repo `signers` package to RS256 (and ES256) and hand-roll
  the JOSE/JWKS/discovery stack.** Rejected: re-implementing security-critical
  JWT signature verification, JWKS fetching + key-rotation caching, and the
  OIDC discovery protocol is exactly the class of code that vetted, widely-used
  libraries exist to provide. A hand-rolled verifier is a large, high-risk
  surface (algorithm-confusion, `alg:none`, key-confusion, JWKS cache
  poisoning) for no benefit. Our `signers` package stays narrowly focused on
  signing *our* tokens with one algorithm we fully control.

- **Use a heavier all-in-one OIDC framework / relying-party toolkit (e.g.
  zitadel/oidc RP).** Rejected: more dependency surface and opinionated
  session/flow handling than we need. We already own state, cookies, and the
  shadow-token mint; we only need discovery + token exchange + ID-token
  verification, which go-oidc + x/oauth2 provide minimally.

- **Lean entirely on `x/oauth2` and skip go-oidc** (verify the ID token
  ourselves). Rejected: `x/oauth2` deliberately does not do OIDC ID-token
  verification or JWKS handling — that is precisely the part go-oidc covers,
  and the part we must not hand-roll (see first alternative).

## Consequences

- New direct dependencies: `github.com/coreos/go-oidc/v3` and
  `golang.org/x/oauth2` (transitively pulls `github.com/go-jose/go-jose/v4`).
- IdP metadata (endpoints + verifier) is cached per issuer with a TTL in
  `OAuthHandler` so discovery/JWKS are not re-fetched on every request; the
  libraries' `RemoteKeySet` additionally caches/refreshes JWKS internally.
- The HTTP client and clock are injectable, so tests stand up an `httptest`
  mock IdP (discovery + JWKS + token endpoint, RS256-signed ID token) and drive
  the real verification path.
- Pinned-endpoint mode (no `discovery_url`) now **requires** an explicit
  `issuer` field in `OIDCConfig` (alongside the three endpoints). The ID-token
  verifier is built with `oidc.NewVerifier(issuer, keySet, cfg)` so the `iss`
  claim **is** validated; `SkipIssuerCheck` is not used. Configuration that
  omits the `issuer` field in pinned mode is rejected at runtime. `discovery_url`
  remains preferred because the library can discover the authoritative issuer
  value automatically.
