package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/keys"
)

// AccessClaims is the decoded payload of an access JWT minted by
// [Loginer.IssueAccessToken].
type AccessClaims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	JTI       string `json:"jti"`
	TokenUse  string `json:"token_use"`
}

// ErrAccessTokenInvalid is the single fail-closed sentinel for every
// access-JWT rejection (missing, malformed, bad signature, expired,
// wrong token_use, wrong audience). Callers map it uniformly to
// unauthenticated so they never leak which check failed.
var ErrAccessTokenInvalid = errors.New("service: invalid or expired access token")

// VerifyAccessToken validates an access JWT offline against the SELF
// issuer's verification keys (the same keys published at /oauth/jwks)
// and returns its claims. It reads the kid from the JWT header, resolves
// the matching verification key, checks the signature, requires
// token_use=="access" (so the shadow's internal JWT — which has no
// token_use — can never pass), checks expiry against now, and (when
// expectedAudience is non-empty) checks the audience. Any failure
// returns [ErrAccessTokenInvalid] — fail closed, no detail leaked.
//
// This is the offline-verification primitive behind authorizer identity
// enrichment: a downstream service that needs only *who* the caller is
// can verify a fresh access JWT without a /authz/check round-trip.
// Function-grant authorization still goes through /authz/check + shadow.
func VerifyAccessToken(ctx context.Context, resolver *keys.Resolver, jwt, expectedAudience string, now time.Time) (*AccessClaims, error) {
	if jwt == "" {
		return nil, ErrAccessTokenInvalid
	}
	kid, err := jwtHeaderKid(jwt)
	if err != nil {
		return nil, ErrAccessTokenInvalid
	}
	lk, err := resolver.VerificationKey(ctx, kid)
	if err != nil {
		return nil, ErrAccessTokenInvalid
	}
	payload, err := lk.Verify(jwt)
	if err != nil {
		return nil, ErrAccessTokenInvalid
	}
	var claims AccessClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrAccessTokenInvalid
	}
	if claims.TokenUse != AccessTokenUse {
		return nil, ErrAccessTokenInvalid
	}
	if claims.Subject == "" {
		return nil, ErrAccessTokenInvalid
	}
	if claims.ExpiresAt == 0 || now.Unix() >= claims.ExpiresAt {
		return nil, ErrAccessTokenInvalid
	}
	if expectedAudience != "" && claims.Audience != expectedAudience {
		return nil, ErrAccessTokenInvalid
	}
	return &claims, nil
}

// newAccessCookie builds the HttpOnly, Secure, SameSite=Lax cookie that
// carries an access JWT to a browser. It is HttpOnly on purpose: the
// token never reaches JavaScript, so it cannot be exfiltrated by XSS.
// Downstream resource servers under the same registrable domain read it
// from the cookie and verify it offline via JWKS. The cookie is scoped
// to ".eTLD+1" (parentCookieDomain) so it flows across the deployment's
// subdomains exactly like the shadow cookie. maxAge is in seconds.
func newAccessCookie(name, value, host string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Domain:   parentCookieDomain(host),
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ── POST /auth/refresh ──

// ShadowIdentifier validates a shadow token and returns its user id
// without a function-grant check. Satisfied by [*Checker.Identify].
type ShadowIdentifier interface {
	Identify(ctx context.Context, token string) (userID string, err error)
}

// AccessTokenMinter mints a short-lived access JWT for an authenticated
// user. Satisfied by [*Loginer.IssueAccessToken].
type AccessTokenMinter interface {
	IssueAccessToken(ctx context.Context, userID, selfIssuerID string) (jwt string, expiresAt int64, err error)
}

// AccessHandler serves POST /auth/refresh: it re-validates the shadow
// cookie (the long-lived session/refresh handle), mints a fresh
// short-lived access JWT, sets it as an HttpOnly access cookie, and
// returns {"expires_in": <seconds>} so a browser SPA can schedule its
// next refresh without ever reading the token. Because every refresh
// re-checks the live shadow (token ISSUED + unexpired, user ACTIVE), a
// revoked shadow immediately stops producing access tokens — the access
// JWT's short TTL bounds how long an already-issued one stays valid.
type AccessHandler struct {
	identifier       ShadowIdentifier
	minter           AccessTokenMinter
	selfIssuerID     string
	shadowCookieName string
	accessCookieName string
	now              func() time.Time
}

// AccessHandlerOption mutates an AccessHandler at construction (for tests).
type AccessHandlerOption func(*AccessHandler)

// WithAccessHandlerClock overrides the time source used to compute
// expires_in / cookie max-age.
func WithAccessHandlerClock(clock func() time.Time) AccessHandlerOption {
	return func(h *AccessHandler) {
		if clock != nil {
			h.now = clock
		}
	}
}

// NewAccessHandler wires the refresh endpoint. identifier and minter are
// required (nil panics, consistent with the other service constructors).
// selfIssuerID defaults to "default"; shadowCookieName to "shadow";
// accessCookieName to shadowCookieName+"_access".
func NewAccessHandler(
	identifier ShadowIdentifier,
	minter AccessTokenMinter,
	selfIssuerID, shadowCookieName, accessCookieName string,
	opts ...AccessHandlerOption,
) *AccessHandler {
	if identifier == nil {
		panic("service.NewAccessHandler: identifier must not be nil")
	}
	if minter == nil {
		panic("service.NewAccessHandler: minter must not be nil")
	}
	if selfIssuerID == "" {
		selfIssuerID = "default"
	}
	if shadowCookieName == "" {
		shadowCookieName = "shadow"
	}
	if accessCookieName == "" {
		accessCookieName = shadowCookieName + "_access"
	}
	h := &AccessHandler{
		identifier:       identifier,
		minter:           minter,
		selfIssuerID:     selfIssuerID,
		shadowCookieName: shadowCookieName,
		accessCookieName: accessCookieName,
		now:              time.Now,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// RegisterRoutes registers POST /auth/refresh on the router.
func (h *AccessHandler) RegisterRoutes(router *protosource.Router) {
	router.Handle("POST", "/auth/refresh", h.handleRefresh)
}

func (h *AccessHandler) handleRefresh(ctx context.Context, req protosource.Request) protosource.Response {
	if !requestIsSecure(req) {
		return accessError(http.StatusForbidden, "https_required")
	}

	shadow := cookieValue(req, h.shadowCookieName)
	if shadow == "" {
		return accessError(http.StatusUnauthorized, "unauthenticated")
	}

	userID, err := h.identifier.Identify(ctx, shadow)
	if err != nil {
		if errors.Is(err, authz.ErrUnauthenticated) {
			return accessError(http.StatusUnauthorized, "unauthenticated")
		}
		return accessError(http.StatusServiceUnavailable, "service_unavailable")
	}

	jwt, expiresAt, err := h.minter.IssueAccessToken(ctx, userID, h.selfIssuerID)
	if err != nil {
		return accessError(http.StatusServiceUnavailable, "service_unavailable")
	}

	now := h.now()
	maxAge := int(time.Unix(expiresAt, 0).Sub(now).Seconds())
	if maxAge <= 0 {
		return accessError(http.StatusServiceUnavailable, "service_unavailable")
	}

	cookie := newAccessCookie(h.accessCookieName, jwt, reqHost(req), maxAge)
	body, _ := json.Marshal(map[string]int{"expires_in": maxAge})
	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
		Cookies:    []*http.Cookie{cookie},
	}
}

func accessError(status int, code string) protosource.Response {
	body, _ := json.Marshal(errorJSON{Error: code, Code: code})
	return protosource.Response{
		StatusCode: status,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

// Ensure AccessHandler satisfies RouteRegistrar and the concrete types
// satisfy the narrow interfaces.
var (
	_ protosource.RouteRegistrar = (*AccessHandler)(nil)
	_ ShadowIdentifier           = (*Checker)(nil)
	_ AccessTokenMinter          = (*Loginer)(nil)
)
