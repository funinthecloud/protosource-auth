// Package loginpage serves a browser login form and handles
// authentication with server-side (configurable name) shadow cookie setting.
// The cookie name is driven by app.Config.ShadowCookieName (v2 prep).
package loginpage

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource-auth/service"
)

//go:embed login.html
var loginHTML string

var loginTmpl = template.Must(template.New("login").Parse(loginHTML))

// Page serves the login form, handles authentication, and sets the
// (configurable) shadow cookie server-side. Implements [protosource.RouteRegistrar].
// The cookie name is configurable to support the v2 federation cookie-rename
// + discovery arc (V2_FEDERATION.md); it defaults to "shadow" for compatibility.
type Page struct {
	issuerID         string
	cookieName       string
	accessCookieName string
	loginer          *service.Loginer
	// minter mints the companion access JWT. It is the same *Loginer in
	// production; the seam (the exported [service.AccessTokenMinter], also used
	// by service.AccessHandler) lets tests inject a failing minter to exercise
	// the fail-closed path.
	minter service.AccessTokenMinter
}

// New returns a Page that serves the login form and handles
// authentication via the provided Loginer. Panics if loginer is nil.
// cookieName defaults to "shadow" if empty; accessCookieName (the
// companion HttpOnly access-JWT cookie) defaults to cookieName+"_access".
func New(issuerID string, cookieName, accessCookieName string, loginer *service.Loginer) *Page {
	if loginer == nil {
		panic("loginpage.New: loginer must not be nil")
	}
	if cookieName == "" {
		cookieName = "shadow"
	}
	if accessCookieName == "" {
		accessCookieName = cookieName + "_access"
	}
	return &Page{
		issuerID:         issuerID,
		cookieName:       cookieName,
		accessCookieName: accessCookieName,
		loginer:          loginer,
		minter:           loginer,
	}
}

// RegisterRoutes registers GET / (form) and POST / (login) on the router.
func (p *Page) RegisterRoutes(router *protosource.Router) {
	router.Handle("GET", "/", p.handlePage)
	router.Handle("POST", "/", p.handleLogin)
}

func (p *Page) handlePage(_ context.Context, req protosource.Request) protosource.Response {
	redirect := queryParam(req, "redirect")
	// Validate redirect URL: must be HTTPS and share the same eTLD+1
	// as the request host to prevent open-redirect attacks.
	if redirect != "" && !isAllowedRedirect(redirect, reqHost(req)) {
		redirect = ""
	}

	var buf bytes.Buffer
	if err := loginTmpl.Execute(&buf, map[string]string{"Redirect": redirect}); err != nil {
		return protosource.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       "internal error",
			Headers:    map[string]string{"Content-Type": "text/plain"},
		}
	}
	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       buf.String(),
		Headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (p *Page) handleLogin(ctx context.Context, req protosource.Request) protosource.Response {
	if !isSecure(req) {
		return jsonError(http.StatusForbidden, "HTTPS is required")
	}

	if !isSameOrigin(req) {
		return jsonError(http.StatusForbidden, "cross-origin request rejected")
	}

	var in loginRequest
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return jsonError(http.StatusBadRequest, "invalid request body")
	}
	if in.Email == "" || in.Password == "" {
		return jsonError(http.StatusBadRequest, "email and password are required")
	}

	result, err := p.loginer.Login(ctx, service.LoginRequest{
		Email:    in.Email,
		Password: in.Password,
		IssuerID: p.issuerID,
	})
	if err != nil {
		return mapLoginError(ctx, err, in.Email)
	}

	maxAge := int(time.Until(time.Unix(result.ExpiresAt, 0)).Seconds())
	if maxAge <= 0 {
		return jsonError(http.StatusServiceUnavailable, "token already expired")
	}

	host := reqHost(req)
	domain := parentDomain(host)

	shadowCookie := &http.Cookie{
		Name:     p.cookieName,
		Value:    result.ShadowToken,
		Path:     "/",
		Domain:   domain,
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// Companion access JWT: a short-lived, offline-verifiable HttpOnly cookie
	// minted for the same user, so the break-glass form login gets the same
	// access-token posture as the federated callback. The token never reaches
	// JS (HttpOnly); the SPA learns only its lifetime via expires_in.
	//
	// A mint failure — or a non-positive lifetime — fails the whole login with
	// 503 rather than returning a partially-initialized session. A shadow cookie
	// with no access cookie would break v2 flows that rely on the access cookie
	// and would silently mask key/JWKS misconfiguration; failing closed makes
	// the misconfiguration visible to operators. Mirrors POST /auth/refresh.
	accessJWT, accessExp, err := p.minter.IssueAccessToken(ctx, result.UserID, p.issuerID)
	if err != nil {
		slog.ErrorContext(ctx, "loginpage: access token mint failed",
			"code", "LOGINPAGE_ACCESS_MINT_FAILED",
			"email", in.Email,
			"error", err,
		)
		return jsonError(http.StatusServiceUnavailable, "service unavailable, please try again")
	}
	accessMaxAge := int(time.Until(time.Unix(accessExp, 0)).Seconds())
	if accessMaxAge <= 0 {
		slog.ErrorContext(ctx, "loginpage: minted access token already expired",
			"code", "LOGINPAGE_ACCESS_EXPIRED",
			"email", in.Email,
		)
		return jsonError(http.StatusServiceUnavailable, "service unavailable, please try again")
	}

	cookies := []*http.Cookie{
		shadowCookie,
		{
			Name:     p.accessCookieName,
			Value:    accessJWT,
			Path:     "/",
			Domain:   domain,
			MaxAge:   accessMaxAge,
			Secure:   true,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		},
	}

	body, _ := json.Marshal(map[string]any{"ok": true, "expires_in": accessMaxAge})
	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
		Cookies:    cookies,
	}
}

func mapLoginError(ctx context.Context, err error, email string) protosource.Response {
	switch {
	case errors.Is(err, service.ErrInvalidCredentials):
		return jsonError(http.StatusUnauthorized, "invalid email or password")
	case errors.Is(err, service.ErrUserNotActive):
		return jsonError(http.StatusForbidden, "account is locked")
	case errors.Is(err, service.ErrIssuerNotActive):
		slog.ErrorContext(ctx, "loginpage: issuer not active",
			"code", "LOGINPAGE_ISSUER_NOT_ACTIVE",
			"email", email,
			"error", err,
		)
		return jsonError(http.StatusServiceUnavailable, "service unavailable, please try again")
	default:
		slog.ErrorContext(ctx, "loginpage: unexpected error",
			"code", "LOGINPAGE_UNAVAILABLE",
			"email", email,
			"error", err,
		)
		return jsonError(http.StatusServiceUnavailable, "service unavailable, please try again")
	}
}

func jsonError(status int, message string) protosource.Response {
	body, _ := json.Marshal(map[string]string{"error": message})
	return protosource.Response{
		StatusCode: status,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

// reqHost extracts the host from the request, checking common header casings.
func reqHost(req protosource.Request) string {
	if h := req.Headers["host"]; h != "" {
		return h
	}
	return req.Headers["Host"]
}

// reqHeader returns the first non-empty value for the given header,
// trying lowercase then title-case.
func reqHeader(req protosource.Request, name string) string {
	if v := req.Headers[strings.ToLower(name)]; v != "" {
		return v
	}
	return req.Headers[name]
}

// isSameOrigin validates that the request originates from the same
// registrable domain as the Host header. This prevents login CSRF
// (session swapping) by rejecting POSTs from third-party sites.
//
// Checks the Origin header first (preferred, set by browsers on
// same-origin and cross-origin requests), then falls back to Referer.
// If neither header is present, the request is rejected.
func isSameOrigin(req protosource.Request) bool {
	host := reqHost(req)
	hostDomain := registrableDomain(host)
	if hostDomain == "" {
		return false
	}

	// Prefer Origin (always present on POSTs from modern browsers).
	if origin := reqHeader(req, "Origin"); origin != "" {
		return matchesRegistrableDomain(origin, hostDomain)
	}

	// Fall back to Referer.
	if referer := reqHeader(req, "Referer"); referer != "" {
		return matchesRegistrableDomain(referer, hostDomain)
	}

	return false
}

// matchesRegistrableDomain checks whether a URL string's host shares
// the same registrable domain as the expected domain.
func matchesRegistrableDomain(rawURL, expectedDomain string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return registrableDomain(u.Host) == expectedDomain
}

// registrableDomain extracts the eTLD+1 from a host (with optional
// port). Returns "" for IPs, localhost, and unparseable hosts.
func registrableDomain(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	if net.ParseIP(h) != nil {
		return ""
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return ""
	}
	return etld1
}

// queryParam extracts a single query parameter from the request.
func queryParam(req protosource.Request, key string) string {
	return req.QueryParameters[key]
}

// isAllowedRedirect validates that a redirect URL is HTTPS and shares
// the same eTLD+1 as the host to prevent open-redirect attacks.
func isAllowedRedirect(redirect, host string) bool {
	u, err := url.Parse(redirect)
	if err != nil {
		return false
	}
	if u.Scheme != "https" {
		return false
	}
	hostDomain := registrableDomain(host)
	if hostDomain == "" {
		return false
	}
	return registrableDomain(u.Host) == hostDomain
}

// isSecure returns true if the request arrived over HTTPS, as indicated
// by the X-Forwarded-Proto header set by API Gateway / load balancers.
// Handles comma-separated values from chained proxies (e.g. "https,http")
// and case-insensitive comparison.
func isSecure(req protosource.Request) bool {
	proto := req.Headers["x-forwarded-proto"]
	if proto == "" {
		proto = req.Headers["X-Forwarded-Proto"]
	}
	if proto == "" {
		return false
	}
	// Take the first value (leftmost proxy = client-facing hop).
	if i := strings.IndexByte(proto, ','); i != -1 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}

// parentDomain derives the cookie domain from a Host header value using
// the public suffix list to find the registrable domain (eTLD+1).
//
//	auth.drhayt.com      -> .drhayt.com
//	drhayt.com           -> .drhayt.com
//	auth.example.co.uk   -> .example.co.uk
//	localhost:8080       -> ""
//	[::1]:8080           -> ""
func parentDomain(host string) string {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port
	}

	// Trim IPv6 brackets (SplitHostPort handles this, but the
	// fallback path might not).
	if len(h) > 0 && h[0] == '[' {
		h = h[1:]
		if i := len(h) - 1; i >= 0 && h[i] == ']' {
			h = h[:i]
		}
	}

	if net.ParseIP(h) != nil {
		return ""
	}

	etld1, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err != nil {
		return "" // localhost, single-label, or invalid
	}

	return "." + etld1
}
