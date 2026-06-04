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
// Both the "issuer" field and all endpoint base URLs are derived from the
// configured issuer (cfg.IssuerIss). This ensures the issuer value and
// endpoint URLs share the same base (as required by OIDC clients and as
// shown in the design doc examples). Using the request host/scheme for
// endpoints would risk inconsistency (e.g. localhost vs. canonical IssuerIss,
// alternate hostnames, missing/mis-set X-Forwarded-Proto).
type Discovery struct {
	issuer     string // from cfg.IssuerIss (advertised in "issuer" and used for tokens + endpoint bases)
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
	// Derive the endpoint base from the configured issuer (not the request).
	// This guarantees that the "issuer" value and the base of every
	// advertised endpoint are identical, satisfying OIDC client expectations
	// (see V2_FEDERATION.md example and feedback on consistency).
	base := issuerBase(d.issuer)

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

func issuerBase(iss string) string {
	if iss == "" {
		return "https://localhost"
	}
	// Trim trailing slash so that appending "/oauth/..." produces clean paths
	// and the base matches the issuer value (modulo trailing slash).
	return strings.TrimRight(iss, "/")
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
