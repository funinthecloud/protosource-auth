package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/funinthecloud/protosource"
)

// Discovery serves the OIDC discovery document (openid-configuration flavored)
// and commits the /oauth/* endpoint URL shapes for the v2 federation shift.
// It is always registered (additive, no auth, no repo dependencies) so that
// downstream consumers and the discovery doc itself do not have to change
// when PKCE, JWKS, access JWTs, etc. are implemented.
//
// See V2_FEDERATION.md for the design and the exact JSON shape we target.
// The "issuer" field comes from config (stable logical iss for JWTs);
// endpoint URLs are derived from the request's Host + X-Forwarded-Proto so
// they reflect how the client reached us (works for local dev, proxies,
// Container Apps, etc.).
type Discovery struct {
	issuer     string // from cfg.IssuerIss (advertised in "issuer" and used for tokens)
	cookieName string // cfg.ShadowCookieName (advertised so clients know what cookie to send)
}

// NewDiscovery returns a Discovery registrar. cookieName defaults to "shadow"
// for backward compatibility.
func NewDiscovery(issuer, cookieName string) *Discovery {
	if cookieName == "" {
		cookieName = "shadow"
	}
	return &Discovery{
		issuer:     issuer,
		cookieName: cookieName,
	}
}

// RegisterRoutes registers the discovery document and the stub handlers for
// the OIDC-shaped paths we commit now (per V2_FEDERATION.md "Land v1 with
// cookie-rename + discovery doc").
//
// Primary discovery location: GET /.well-known/openid-configuration
// We also register /oauth/.well-known/openid-configuration as an alias.
//
// The /oauth/* targets are registered with stub 404 responses so the paths
// exist in the router today (clients and generated docs can see the contract)
// even though the real PKCE/JWKS/userinfo behavior lands in later phases.
func (d *Discovery) RegisterRoutes(router *protosource.Router) {
	router.Handle("GET", "/.well-known/openid-configuration", d.handleDiscovery)
	router.Handle("GET", "/oauth/.well-known/openid-configuration", d.handleDiscovery)

	// Commit the endpoint shapes (GET/POST as appropriate for the future
	// flows). Real implementations replace these stubs.
	router.Handle("GET", "/oauth/authorize", d.stubNotImplemented)
	router.Handle("GET", "/oauth/callback", d.stubNotImplemented)
	router.Handle("POST", "/oauth/token", d.stubNotImplemented)
	router.Handle("GET", "/oauth/userinfo", d.stubNotImplemented)
	router.Handle("GET", "/oauth/jwks", d.stubNotImplemented)
	router.Handle("GET", "/oauth/logout", d.stubNotImplemented)
	router.Handle("POST", "/oauth/logout", d.stubNotImplemented)
}

func (d *Discovery) handleDiscovery(ctx context.Context, req protosource.Request) protosource.Response {
	scheme := "https"
	if !isSecure(req) {
		scheme = "http"
	}
	host := reqHost(req)
	if host == "" {
		// Should not happen in real requests, but keep the handler robust.
		host = "localhost"
	}
	base := scheme + "://" + host

	doc := map[string]any{
		"issuer":                 d.issuer,
		"authorization_endpoint": base + "/oauth/authorize",
		"token_endpoint":         base + "/oauth/token",
		"userinfo_endpoint":      base + "/oauth/userinfo",
		"jwks_uri":               base + "/oauth/jwks",
		"end_session_endpoint":   base + "/oauth/logout",
		"cookie_name":            d.cookieName,
		"response_types_supported":          []string{"code"},
		"grant_types_supported":             []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":  []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"id_token_signing_alg_values_supported": []string{"EdDSA", "RS256"},
	}

	b, err := json.Marshal(doc)
	if err != nil {
		return protosource.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       `{"error":"internal_error"}`,
			Headers:    map[string]string{"Content-Type": "application/json"},
		}
	}
	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       string(b),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

func (d *Discovery) stubNotImplemented(ctx context.Context, req protosource.Request) protosource.Response {
	// These paths are intentionally registered (even while returning 404)
	// so that the OIDC discovery document can advertise stable URLs today.
	// This fulfills the "commit the URL shape on v1" requirement from
	// V2_FEDERATION.md. Real behavior (PKCE, ID token exchange, JWKS
	// publication, access JWTs, etc.) is added in later phases.
	body, _ := json.Marshal(map[string]string{
		"error":             "not_implemented",
		"error_description": "This endpoint shape is committed for v2 federation (see /.well-known/openid-configuration). Implementation is in progress.",
	})
	return protosource.Response{
		StatusCode: http.StatusNotFound,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

// --- request helpers (duplicated from loginpage for URL construction) ---
//
// These match the header handling used for the login page (Host +
// X-Forwarded-Proto with comma support for chained proxies) so that
// discovery advertises the same base the client is using. In a future
// cleanup we can extract a small shared helper (internal/httputil or
// similar) once more v2 pieces need it.

func reqHost(req protosource.Request) string {
	if h := req.Headers["host"]; h != "" {
		return h
	}
	return req.Headers["Host"]
}

func isSecure(req protosource.Request) bool {
	proto := req.Headers["x-forwarded-proto"]
	if proto == "" {
		proto = req.Headers["X-Forwarded-Proto"]
	}
	if proto == "" {
		return false
	}
	if i := strings.IndexByte(proto, ','); i != -1 {
		proto = proto[:i]
	}
	return strings.EqualFold(strings.TrimSpace(proto), "https")
}
