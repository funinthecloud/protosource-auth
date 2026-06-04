package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/service"
)

func TestDiscoveryReturnsCanonicalOIDCConfig(t *testing.T) {
	issuer := "https://auth.fitc.drhayt.com"
	cookie := "shadow_azure"

	d := service.NewDiscovery(issuer, cookie)
	router := protosource.NewRouter(d)

	for _, path := range []string{"/.well-known/openid-configuration", "/oauth/.well-known/openid-configuration"} {
		t.Run(path, func(t *testing.T) {
			req := protosource.Request{
				Headers: map[string]string{
					// Even if the request arrives via a different host or scheme,
					// the discovery must use the configured issuer base for
					// OIDC issuer/endpoint consistency.
					"host":              "localhost:8080",
					"x-forwarded-proto": "http",
				},
			}

			got := router.Dispatch(context.Background(), "GET", path, req)
			if got.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 for %s, got %d: %s", path, got.StatusCode, got.Body)
			}
			if ct := got.Headers["Content-Type"]; ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			var doc map[string]any
			if err := json.Unmarshal([]byte(got.Body), &doc); err != nil {
				t.Fatalf("decode discovery: %v", err)
			}

			if gotIssuer := doc["issuer"]; gotIssuer != issuer {
				t.Errorf("issuer = %v, want %q", gotIssuer, issuer)
			}
			if gotCookie := doc["cookie_name"]; gotCookie != cookie {
				t.Errorf("cookie_name = %v, want %q", gotCookie, cookie)
			}

			// All endpoints must share the exact same base as the issuer (no
			// request-derived host/scheme leaking in). This matches the
			// single-base example in V2_FEDERATION.md.
			for _, key := range []string{
				"authorization_endpoint",
				"token_endpoint",
				"userinfo_endpoint",
				"jwks_uri",
				"end_session_endpoint",
			} {
				ep, _ := doc[key].(string)
				if !strings.HasPrefix(ep, issuer+"/oauth/") && ep != issuer+"/oauth/"+strings.TrimPrefix(key, "_endpoint") {
					// simple check: must start with the issuer base
					if !strings.HasPrefix(ep, issuer) {
						t.Errorf("%s = %q does not share base with issuer %q", key, ep, issuer)
					}
				}
			}

			// Spot-check one fully
			if authz := doc["authorization_endpoint"]; authz != issuer+"/oauth/authorize" {
				t.Errorf("authorization_endpoint = %v, want %s/oauth/authorize", authz, issuer)
			}

			// Supported lists (exact per design)
			if rt, ok := doc["response_types_supported"].([]any); !ok || len(rt) != 1 || rt[0] != "code" {
				t.Errorf("response_types_supported = %v", doc["response_types_supported"])
			}
			if gt, ok := doc["grant_types_supported"].([]any); !ok || len(gt) != 2 {
				t.Errorf("grant_types_supported = %v", doc["grant_types_supported"])
			}
			if cc, ok := doc["code_challenge_methods_supported"].([]any); !ok || len(cc) != 1 || cc[0] != "S256" {
				t.Errorf("code_challenge_methods_supported = %v", doc["code_challenge_methods_supported"])
			}
			if te, ok := doc["token_endpoint_auth_methods_supported"].([]any); !ok || len(te) != 1 || te[0] != "none" {
				t.Errorf("token_endpoint_auth_methods_supported = %v", doc["token_endpoint_auth_methods_supported"])
			}
			if algs, ok := doc["id_token_signing_alg_values_supported"].([]any); !ok || len(algs) != 2 {
				t.Errorf("id_token_signing_alg_values_supported = %v", doc["id_token_signing_alg_values_supported"])
			}
		})
	}
}

func TestDiscoveryStubsReturnNotImplemented(t *testing.T) {
	d := service.NewDiscovery("https://auth.example.com", "shadow")
	router := protosource.NewRouter(d)

	cases := []struct {
		method string
		path   string
	}{
		{"GET", "/oauth/authorize"},
		{"GET", "/oauth/callback"},
		{"POST", "/oauth/token"},
		{"GET", "/oauth/userinfo"},
		{"GET", "/oauth/logout"},
		{"POST", "/oauth/logout"},
	}

	for _, c := range cases {
		t.Run(c.method+" "+c.path, func(t *testing.T) {
			req := protosource.Request{}
			got := router.Dispatch(context.Background(), c.method, c.path, req)
			if got.StatusCode != http.StatusNotFound {
				t.Fatalf("expected 404, got %d: %s", got.StatusCode, got.Body)
			}
			var body struct {
				Error            string `json:"error"`
				ErrorDescription string `json:"error_description"`
			}
			if err := json.Unmarshal([]byte(got.Body), &body); err != nil {
				t.Fatalf("decode stub body: %v", err)
			}
			if body.Error != "not_implemented" {
				t.Errorf("error = %q, want not_implemented", body.Error)
			}
			if !strings.Contains(body.ErrorDescription, "committed for v2 federation") {
				t.Errorf("error_description = %q, want mention of committed for v2", body.ErrorDescription)
			}
		})
	}
}

func TestDiscoveryDefaultsCookieName(t *testing.T) {
	d := service.NewDiscovery("https://auth.example.com", "") // empty -> default
	router := protosource.NewRouter(d)

	got := router.Dispatch(context.Background(), "GET", "/.well-known/openid-configuration", protosource.Request{})
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status %d", got.StatusCode)
	}

	var doc map[string]any
	json.Unmarshal([]byte(got.Body), &doc)
	if doc["cookie_name"] != "shadow" {
		t.Errorf("cookie_name with empty = %v, want shadow", doc["cookie_name"])
	}
}