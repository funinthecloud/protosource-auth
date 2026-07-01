package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/funinthecloud/protosource"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	"github.com/funinthecloud/protosource-auth/internal/httputil"
	"github.com/funinthecloud/protosource-auth/keys"
)

// OAuthHandler implements the federated-login OAuth2/OIDC authorization-code
// flow with PKCE (Track A): GET /oauth/authorize redirects the browser to an
// external IdP, and GET /oauth/callback finishes the exchange, mints a shadow
// token for the resolved local user, and sets the shadow cookie.
//
// It owns only the PKCE plumbing. User provisioning is delegated to the
// committed IdentityResolver seam (service/federation.go): the callback
// terminates in a signature-verified FederatedIdentity and calls
// ResolveOrProvision to get a local user id. Everything IdP-side (discovery,
// JWKS-backed ID-token verification, token exchange) goes through
// coreos/go-oidc + x/oauth2 — see docs/decisions for why. Our own state
// cookie is signed/verified with OUR keys.Resolver (EdDSA), independent of
// the IdP side.
type OAuthHandler struct {
	issuerRepo AggregateRepo
	oidc       *OIDCConfigurator // for DecryptClientSecret only
	resolver   *keys.Resolver
	loginer    *Loginer
	identity   IdentityResolver

	// selfIssuerID is OUR SELF issuer (signs the state cookie + the minted
	// shadow JWT). issuerIss is its public base URL (cfg.IssuerIss), used to
	// build the IdP-facing redirect_uri (our /oauth/callback).
	selfIssuerID string
	issuerIss    string
	stateAlg     string // algorithm used to sign the state cookie (e.g. EdDSA)

	// shadowCookieName / stateCookieName / accessCookieName are the cookie
	// names; stateTTL is the state cookie + JWT lifetime.
	shadowCookieName string
	stateCookieName  string
	accessCookieName string
	stateTTL         time.Duration

	// httpClient and now are injectable for tests. httpClient is handed to
	// both go-oidc (via oidc.ClientContext) and x/oauth2 (via the
	// oauth2.HTTPClient context value).
	httpClient *http.Client
	now        func() time.Time

	// metaMu guards metaCache, the per-issuer cache of resolved IdP metadata
	// (auth/token endpoints + ID-token verifier) so discovery/JWKS are not
	// re-fetched on every authorize/callback.
	metaMu    sync.Mutex
	metaCache map[string]*oidcMeta
	metaTTL   time.Duration
}

// DefaultStateTTL is how long a federated-login attempt may stay in flight:
// the lifetime of the signed state cookie between /oauth/authorize and the
// IdP redirect back to /oauth/callback.
const DefaultStateTTL = 10 * time.Minute

// defaultMetaTTL is how long resolved IdP metadata is cached per issuer.
const defaultMetaTTL = time.Hour

// federatedScopes are the OIDC scopes requested from the IdP.
var federatedScopes = []string{oidc.ScopeOpenID, "email", "profile"}

// OAuthHandlerOption mutates an OAuthHandler at construction (for tests).
type OAuthHandlerOption func(*OAuthHandler)

// WithOAuthHTTPClient overrides the HTTP client used for IdP discovery, JWKS,
// and token exchange. Defaults to http.DefaultClient.
func WithOAuthHTTPClient(c *http.Client) OAuthHandlerOption {
	return func(h *OAuthHandler) {
		if c != nil {
			h.httpClient = c
		}
	}
}

// WithOAuthClock overrides the time source (state TTL + ID-token verification).
func WithOAuthClock(clock func() time.Time) OAuthHandlerOption {
	return func(h *OAuthHandler) {
		if clock != nil {
			h.now = clock
		}
	}
}

// WithOAuthStateTTL overrides the state cookie lifetime.
func WithOAuthStateTTL(d time.Duration) OAuthHandlerOption {
	return func(h *OAuthHandler) {
		if d > 0 {
			h.stateTTL = d
		}
	}
}

// WithOAuthAccessCookieName overrides the name of the access-JWT cookie
// set on a successful callback. Empty leaves the default
// (shadowCookieName + "_access").
func WithOAuthAccessCookieName(name string) OAuthHandlerOption {
	return func(h *OAuthHandler) {
		if name != "" {
			h.accessCookieName = name
		}
	}
}

// NewOAuthHandler wires the PKCE handler. issuerRepo, configurator, resolver,
// loginer, and identity are required (nil panics, consistent with the other
// service constructors). selfIssuerID defaults to "default", shadowCookieName
// to "shadow".
func NewOAuthHandler(
	issuerRepo AggregateRepo,
	configurator *OIDCConfigurator,
	resolver *keys.Resolver,
	loginer *Loginer,
	identity IdentityResolver,
	selfIssuerID, issuerIss, shadowCookieName string,
	opts ...OAuthHandlerOption,
) *OAuthHandler {
	if issuerRepo == nil {
		panic("service.NewOAuthHandler: issuerRepo must not be nil")
	}
	if configurator == nil {
		panic("service.NewOAuthHandler: configurator must not be nil")
	}
	if resolver == nil {
		panic("service.NewOAuthHandler: resolver must not be nil")
	}
	if loginer == nil {
		panic("service.NewOAuthHandler: loginer must not be nil")
	}
	if identity == nil {
		panic("service.NewOAuthHandler: identity must not be nil")
	}
	if selfIssuerID == "" {
		selfIssuerID = "default"
	}
	if shadowCookieName == "" {
		shadowCookieName = "shadow"
	}
	h := &OAuthHandler{
		issuerRepo:       issuerRepo,
		oidc:             configurator,
		resolver:         resolver,
		loginer:          loginer,
		identity:         identity,
		selfIssuerID:     selfIssuerID,
		issuerIss:        issuerIss,
		stateAlg:         preferredAlg(resolver),
		shadowCookieName: shadowCookieName,
		stateCookieName:  shadowCookieName + "_oauth_state",
		accessCookieName: shadowCookieName + "_access",
		stateTTL:         DefaultStateTTL,
		httpClient:       http.DefaultClient,
		now:              time.Now,
		metaCache:        make(map[string]*oidcMeta),
		metaTTL:          defaultMetaTTL,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// preferredAlg picks the algorithm used to sign the state cookie. The kid in
// the JWT header carries the algorithm, so verification works regardless of
// which supported alg is chosen; we prefer EdDSA when present for determinism.
func preferredAlg(resolver *keys.Resolver) string {
	algs := resolver.SupportedAlgorithms()
	for _, a := range algs {
		if a == "EdDSA" {
			return a
		}
	}
	if len(algs) > 0 {
		return algs[0]
	}
	return "EdDSA"
}

// RegisterRoutes registers the two real PKCE endpoints. These replace the
// Discovery stubs for the same paths (Discovery no longer registers them).
func (h *OAuthHandler) RegisterRoutes(router *protosource.Router) {
	router.Handle("GET", "/oauth/authorize", h.HandleAuthorize)
	router.Handle("GET", "/oauth/callback", h.HandleCallback)
}

// Ensure OAuthHandler satisfies RouteRegistrar.
var _ protosource.RouteRegistrar = (*OAuthHandler)(nil)

// ── /oauth/authorize ──

// HandleAuthorize begins a federated login. It validates the request, mints a
// PKCE verifier + signed state cookie, and 302-redirects the browser to the
// chosen IdP's authorization endpoint.
func (h *OAuthHandler) HandleAuthorize(ctx context.Context, req protosource.Request) protosource.Response {
	if !httputil.IsSecure(req) {
		return oauthRedirectError(http.StatusForbidden, "https_required")
	}

	idp := req.QueryParameters["idp"]
	if idp == "" {
		return oauthRedirectError(http.StatusBadRequest, "missing_idp")
	}

	oc, resp, ok := h.loadExternalOIDC(ctx, idp)
	if !ok {
		return resp
	}

	host := httputil.ReqHost(req)
	redirectURI := req.QueryParameters["redirect_uri"]
	if redirectURI == "" {
		redirectURI = "/" // post-login default: our own host root
	} else if !httputil.IsAllowedRedirect(redirectURI, host) {
		return oauthRedirectError(http.StatusBadRequest, "invalid_redirect_uri")
	}

	meta, err := h.oidcMetaFor(ctx, idp, oc)
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "idp_unavailable")
	}

	verifier, err := generateVerifier()
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "internal_error")
	}
	state, err := generateOpaqueToken() // random CSRF nonce echoed via the IdP
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "internal_error")
	}

	now := h.now()
	stateJWT, err := signState(ctx, h.resolver, h.selfIssuerID, h.stateAlg,
		verifier, redirectURI, state, idp, now, h.stateTTL)
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "internal_error")
	}

	conf := &oauth2.Config{
		ClientID:    oc.GetClientId(),
		RedirectURL: h.callbackURL(),
		Scopes:      federatedScopes,
		Endpoint:    oauth2.Endpoint{AuthURL: meta.authURL, TokenURL: meta.tokenURL},
	}
	authCodeURL := conf.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", s256Challenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	stateCookie := &http.Cookie{
		Name:     h.stateCookieName,
		Value:    stateJWT,
		Path:     "/oauth/callback",
		Domain:   httputil.ParentDomain(host),
		MaxAge:   int(h.stateTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax: sent on the IdP's top-level GET redirect back
	}

	return protosource.Response{
		StatusCode: http.StatusFound,
		Headers: map[string]string{
			"Location":   authCodeURL,
			"Set-Cookie": stateCookie.String(),
		},
	}
}

// ── /oauth/callback ──

// HandleCallback finishes a federated login: it verifies the state cookie,
// exchanges the authorization code for tokens at the IdP, verifies the ID
// token against the IdP's JWKS, resolves a local user, mints a shadow token,
// and 302-redirects back to the originally requested redirect_uri with the
// shadow cookie set.
func (h *OAuthHandler) HandleCallback(ctx context.Context, req protosource.Request) protosource.Response {
	if !httputil.IsSecure(req) {
		return oauthRedirectError(http.StatusForbidden, "https_required")
	}

	// Relay an IdP-side error (e.g. user denied consent) as a 400.
	if e := req.QueryParameters["error"]; e != "" {
		return oauthRedirectError(http.StatusBadRequest, "idp_error")
	}

	code := req.QueryParameters["code"]
	stateParam := req.QueryParameters["state"]
	if code == "" || stateParam == "" {
		return oauthRedirectError(http.StatusBadRequest, "missing_code_or_state")
	}

	now := h.now()
	stateJWT := httputil.CookieValue(req, h.stateCookieName)
	claims, err := verifyState(ctx, h.resolver, stateJWT, stateParam, now)
	if err != nil {
		// Covers missing/tampered/expired cookie and state mismatch.
		return oauthRedirectError(http.StatusBadRequest, "invalid_state")
	}

	oc, resp, ok := h.loadExternalOIDC(ctx, claims.IDP)
	if !ok {
		return resp
	}

	secret, err := h.oidc.DecryptClientSecret(ctx, oc)
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "idp_unavailable")
	}

	meta, err := h.oidcMetaFor(ctx, claims.IDP, oc)
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "idp_unavailable")
	}

	cctx := h.idpContext(ctx)
	conf := &oauth2.Config{
		ClientID:     oc.GetClientId(),
		ClientSecret: string(secret),
		RedirectURL:  h.callbackURL(),
		Scopes:       federatedScopes,
		Endpoint:     oauth2.Endpoint{AuthURL: meta.authURL, TokenURL: meta.tokenURL},
	}
	token, err := conf.Exchange(cctx, code, oauth2.VerifierOption(claims.Verifier))
	if err != nil {
		return oauthRedirectError(http.StatusBadGateway, "token_exchange_failed")
	}

	rawID, _ := token.Extra("id_token").(string)
	if rawID == "" {
		return oauthRedirectError(http.StatusBadGateway, "missing_id_token")
	}
	idToken, err := meta.verifier.Verify(cctx, rawID)
	if err != nil {
		return oauthRedirectError(http.StatusUnauthorized, "id_token_invalid")
	}
	if !audienceMatches(idToken, oc.GetClientId(), oc.GetAllowedAudiences()) {
		return oauthRedirectError(http.StatusUnauthorized, "id_token_invalid")
	}

	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err != nil {
		return oauthRedirectError(http.StatusUnauthorized, "id_token_invalid")
	}

	fi := FederatedIdentity{
		IssuerID: claims.IDP,
		Subject:  idToken.Subject,
		Email:    emailFromClaims(allClaims, oc),
		Claims:   allClaims,
	}

	userID, err := h.identity.ResolveOrProvision(ctx, fi, oc)
	if err != nil {
		if errors.Is(err, ErrJITRejected) {
			return oauthRedirectError(http.StatusForbidden, "jit_rejected")
		}
		return oauthRedirectError(http.StatusServiceUnavailable, "provisioning_failed")
	}

	loginResp, err := h.loginer.IssueForUser(ctx, userID, h.selfIssuerID)
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "token_issue_failed")
	}

	// Companion access JWT: short-lived, offline-verifiable, delivered as a
	// separate HttpOnly cookie alongside the shadow. The shadow stays the
	// long-lived session/refresh handle; the access cookie is the thing
	// downstream resource servers verify via JWKS without a /authz/check hop.
	accessJWT, accessExp, err := h.loginer.IssueAccessToken(ctx, userID, h.selfIssuerID)
	if err != nil {
		return oauthRedirectError(http.StatusServiceUnavailable, "token_issue_failed")
	}

	host := httputil.ReqHost(req)
	shadowMaxAge := int(time.Unix(loginResp.ExpiresAt, 0).Sub(now).Seconds())
	accessMaxAge := int(time.Unix(accessExp, 0).Sub(now).Seconds())
	if shadowMaxAge <= 0 || accessMaxAge <= 0 {
		return oauthRedirectError(http.StatusServiceUnavailable, "token_issue_failed")
	}

	shadowCookie := &http.Cookie{
		Name:     h.shadowCookieName,
		Value:    loginResp.ShadowToken,
		Path:     "/",
		Domain:   httputil.ParentDomain(host),
		MaxAge:   shadowMaxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	accessCookie := newAccessCookie(h.accessCookieName, accessJWT, host, accessMaxAge)

	// Now that protosource v0.8.0 Response carries Cookies []*http.Cookie
	// (one Set-Cookie per entry), actively clear the single-use state cookie
	// in the same response — no longer relying on it self-expiring.
	clearedState := &http.Cookie{
		Name:     h.stateCookieName,
		Value:    "",
		Path:     "/oauth/callback",
		Domain:   httputil.ParentDomain(host),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	return protosource.Response{
		StatusCode: http.StatusFound,
		Headers:    map[string]string{"Location": claims.RedirectURI},
		Cookies:    []*http.Cookie{shadowCookie, accessCookie, clearedState},
	}
}

// ── IdP metadata resolution + caching ──

// oidcMeta is the resolved, cacheable per-issuer IdP metadata: the OAuth2
// authorization/token endpoints and an ID-token verifier bound to the IdP's
// JWKS.
type oidcMeta struct {
	authURL  string
	tokenURL string
	verifier *oidc.IDTokenVerifier
	fetched  time.Time
}

// oidcMetaFor returns cached IdP metadata for issuerID, building it on a miss
// or after metaTTL. When the OIDCConfig has a discovery_url, go-oidc fetches
// the discovery document (endpoints + JWKS); otherwise the pinned endpoints +
// jwks_uri are used directly.
func (h *OAuthHandler) oidcMetaFor(ctx context.Context, issuerID string, oc *issuerv1.OIDCConfig) (*oidcMeta, error) {
	h.metaMu.Lock()
	if m, ok := h.metaCache[issuerID]; ok && h.now().Sub(m.fetched) < h.metaTTL {
		h.metaMu.Unlock()
		return m, nil
	}
	h.metaMu.Unlock()

	m, err := h.buildOIDCMeta(ctx, oc)
	if err != nil {
		return nil, err
	}
	m.fetched = h.now()

	h.metaMu.Lock()
	h.metaCache[issuerID] = m
	h.metaMu.Unlock()
	return m, nil
}

func (h *OAuthHandler) buildOIDCMeta(ctx context.Context, oc *issuerv1.OIDCConfig) (*oidcMeta, error) {
	cctx := h.idpContext(ctx)
	cfg := &oidc.Config{ClientID: oc.GetClientId(), Now: h.now}
	if len(oc.GetAllowedAudiences()) > 0 {
		cfg.SkipClientIDCheck = true
	}

	if du := oc.GetDiscoveryUrl(); du != "" {
		// go-oidc's NewProvider takes the IdP *issuer base* URL and appends
		// /.well-known/openid-configuration itself. Operators (and the admin
		// UI placeholder) routinely paste the full discovery-document URL, so
		// accept either form: strip a trailing well-known suffix before the
		// fetch to avoid a double-/.well-known/ path that would 404.
		provider, err := oidc.NewProvider(cctx, issuerBaseFromDiscoveryURL(du))
		if err != nil {
			return nil, err
		}
		ep := provider.Endpoint()
		return &oidcMeta{
			authURL:  ep.AuthURL,
			tokenURL: ep.TokenURL,
			verifier: provider.Verifier(cfg),
		}, nil
	}

	// Pinned-endpoint mode: no discovery document, so we cannot learn the
	// IdP's canonical issuer string to enforce the `iss` claim. Verify
	// signature + audience + expiry against the configured JWKS and skip the
	// issuer check. Prefer discovery_url for full iss validation.
	// ponytail: acceptable for pinned deployments (iss check skipped); audiences
	// now handled (SkipClientIDCheck + audienceMatches when allowed_audiences set).
	//
	// All three endpoints are required: without authorization_endpoint or
	// token_endpoint, /oauth/authorize would build a redirect (and later a
	// token exchange) against an empty URL. Fail closed at config-resolution
	// time instead of producing a malformed redirect at runtime.
	var missing []string
	if oc.GetAuthorizationEndpoint() == "" {
		missing = append(missing, "authorization_endpoint")
	}
	if oc.GetTokenEndpoint() == "" {
		missing = append(missing, "token_endpoint")
	}
	if oc.GetJwksUri() == "" {
		missing = append(missing, "jwks_uri")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("service: pinned OIDC config (no discovery_url) is missing required %s", strings.Join(missing, ", "))
	}
	cfg.SkipIssuerCheck = true
	keySet := oidc.NewRemoteKeySet(cctx, oc.GetJwksUri())
	return &oidcMeta{
		authURL:  oc.GetAuthorizationEndpoint(),
		tokenURL: oc.GetTokenEndpoint(),
		verifier: oidc.NewVerifier("", keySet, cfg),
	}, nil
}

// issuerBaseFromDiscoveryURL normalizes a configured discovery_url to the IdP
// issuer base that go-oidc's NewProvider expects. NewProvider appends
// /.well-known/openid-configuration itself, so if the operator pasted the full
// discovery-document URL (as the admin UI placeholder suggests) we strip that
// suffix to avoid a duplicated path. A bare issuer base is returned unchanged.
func issuerBaseFromDiscoveryURL(du string) string {
	const wellKnown = "/.well-known/openid-configuration"
	trimmed := strings.TrimRight(du, "/")
	if base, ok := strings.CutSuffix(trimmed, wellKnown); ok {
		return base
	}
	// A trailing slash on a bare issuer base would make go-oidc fetch a
	// double-slash path and fail its exact issuer-string comparison, so drop it.
	return trimmed
}

// audienceMatches reports whether the ID token's aud claim satisfies the
// clientID or one of the allowed_audiences. Called after verifier.Verify
// when we set SkipClientIDCheck (i.e. when allowed_audiences is non-empty).
// Empty allowed list is not passed here (verifier enforces clientID instead).
func audienceMatches(idToken *oidc.IDToken, clientID string, allowed []string) bool {
	for _, a := range idToken.Audience {
		if a == clientID {
			return true
		}
		for _, w := range allowed {
			if a == w {
				return true
			}
		}
	}
	return false
}

// idpContext returns a context carrying our injectable HTTP client for both
// go-oidc (oidc.ClientContext) and x/oauth2 (oauth2.HTTPClient).
func (h *OAuthHandler) idpContext(ctx context.Context) context.Context {
	cctx := oidc.ClientContext(ctx, h.httpClient)
	return context.WithValue(cctx, oauth2.HTTPClient, h.httpClient)
}

// callbackURL is our IdP-facing redirect_uri, derived from the configured
// issuer base (cfg.IssuerIss) so it matches what is registered with the IdP
// and what the discovery document advertises.
func (h *OAuthHandler) callbackURL() string {
	return issuerBase(h.issuerIss) + "/oauth/callback"
}

// loadExternalOIDC loads issuerID and verifies it is an ACTIVE, KIND_EXTERNAL
// issuer with non-nil OIDC config. On failure it returns ok=false plus a ready
// response (404 for not found, 400 for not-eligible, 503 for store errors).
func (h *OAuthHandler) loadExternalOIDC(ctx context.Context, issuerID string) (*issuerv1.OIDCConfig, protosource.Response, bool) {
	agg, err := h.issuerRepo.Load(ctx, issuerID)
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			return nil, oauthRedirectError(http.StatusNotFound, "unknown_idp"), false
		}
		return nil, oauthRedirectError(http.StatusServiceUnavailable, "idp_unavailable"), false
	}
	iss, ok := agg.(*issuerv1.Issuer)
	if !ok {
		return nil, oauthRedirectError(http.StatusServiceUnavailable, "idp_unavailable"), false
	}
	if iss.GetState() != issuerv1.State_STATE_ACTIVE ||
		iss.GetKind() != issuerv1.Kind_KIND_EXTERNAL ||
		iss.GetOidc() == nil {
		return nil, oauthRedirectError(http.StatusBadRequest, "idp_not_eligible"), false
	}
	return iss.GetOidc(), protosource.Response{}, true
}

// emailFromClaims extracts the email from the ID-token claims using the
// issuer's claim_map: claim_map["email_at_link"] names the IdP claim that
// holds the email (defaulting to the standard "email" claim).
func emailFromClaims(claims map[string]any, oc *issuerv1.OIDCConfig) string {
	name := oc.GetClaimMap()["email_at_link"]
	if name == "" {
		name = "email"
	}
	if v, ok := claims[name].(string); ok {
		return v
	}
	return ""
}

// oauthRedirectError returns a small JSON error body. Secrets are never
// echoed; the code is a stable, non-sensitive label.
func oauthRedirectError(status int, code string) protosource.Response {
	body, _ := json.Marshal(errorJSON{Error: code, Code: code})
	return protosource.Response{
		StatusCode: status,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

// Cookie/redirect helpers have been deduplicated into internal/httputil
// (ReqHost, ReqHeader, IsSecure, RegistrableDomain, ParentDomain,
// IsAllowedRedirect, CookieValue). Call sites updated; old local copies removed.
// (This resolves the prior duplication noted for loginpage + service.)
