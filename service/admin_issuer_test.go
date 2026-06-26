package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/authz/directauthz"
	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/service"
)

// adminIssuerRig stands up an authenticated admin with admin.issuer.v1.*
// grants, seeds a KIND_EXTERNAL issuer to configure, and returns the router,
// the shadow cookie value, the live configurator (for decrypt assertions), and
// the external issuer id. It is the issuer analogue of adminRig.
func adminIssuerRig(t *testing.T, grants []string) (*protosource.Router, *service.OIDCConfigurator, service.AggregateRepo, string, string) {
	t.Helper()
	ctx := context.Background()

	rig := newE2ERig(t)
	_, _ = rig.seed(t, "admin@example.com", "admin-pass", grants)

	resp, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email:    "admin@example.com",
		Password: "admin-pass",
		IssuerID: "issuer-self",
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// A KIND_EXTERNAL issuer to point the OIDC config at.
	const extID = "ext-1"
	if _, err := rig.issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: extID, Actor: "bootstrap", Iss: "https://idp.example.com",
		DisplayName: "External", Kind: issuerv1.Kind_KIND_EXTERNAL,
	}); err != nil {
		t.Fatalf("seed external issuer: %v", err)
	}

	master, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(master)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	configurator := service.NewOIDCConfigurator(rig.issuerRepo, provider, "local-master")

	az := directauthz.New(rig.checker, directauthz.WithTokenSource(httpauthz.Cookie("shadow")))
	admin := service.NewAdminIssuer(configurator, az)
	router := protosource.NewRouter(admin)

	return router, configurator, rig.issuerRepo, resp.ShadowToken, extID
}

// secureHeaders returns the request headers an authenticated, HTTPS admin call
// carries: the shadow cookie plus the proxy's X-Forwarded-Proto.
func secureHeaders(token string) map[string]string {
	return map[string]string{
		"Cookie":            "shadow=" + token,
		"X-Forwarded-Proto": "https",
	}
}

func TestAdminSetOIDC_HappyPathWrapsSecret(t *testing.T) {
	router, cfg, repo, token, extID := adminIssuerRig(t, []string{"admin.issuer.v1.*"})
	ctx := context.Background()

	got := router.Dispatch(ctx, "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: secureHeaders(token),
		Body:    `{"issuer_id":"` + extID + `","client_id":"client-abc","client_secret":"s3cr3t","discovery_url":"https://idp.example.com"}`,
	})
	if got.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", got.StatusCode, got.Body)
	}

	// The plaintext secret must have been wrapped (never stored as-is) and must
	// round-trip back to the original through the configurator's provider.
	oc := loadOIDC(t, ctx, repo, extID)
	if len(oc.GetWrappedClientSecret()) == 0 {
		t.Fatal("wrapped_client_secret not set")
	}
	plain, err := cfg.DecryptClientSecret(ctx, oc)
	if err != nil {
		t.Fatalf("DecryptClientSecret: %v", err)
	}
	if string(plain) != "s3cr3t" {
		t.Fatalf("decrypted secret = %q, want s3cr3t", plain)
	}
}

// A blank client_secret on a follow-up update must preserve the previously
// wrapped secret (endpoint/policy-only edits must not clobber credentials).
func TestAdminSetOIDC_BlankSecretPreservesPriorWrapped(t *testing.T) {
	router, cfg, repo, token, extID := adminIssuerRig(t, []string{"admin.issuer.v1.*"})
	ctx := context.Background()

	// First set with a real secret.
	if got := router.Dispatch(ctx, "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: secureHeaders(token),
		Body:    `{"issuer_id":"` + extID + `","client_id":"client-abc","client_secret":"original-secret"}`,
	}); got.StatusCode != http.StatusOK {
		t.Fatalf("initial set: expected 200, got %d: %s", got.StatusCode, got.Body)
	}

	// Now update an endpoint with NO secret supplied.
	if got := router.Dispatch(ctx, "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: secureHeaders(token),
		Body:    `{"issuer_id":"` + extID + `","client_id":"client-abc","discovery_url":"https://idp.example.com"}`,
	}); got.StatusCode != http.StatusOK {
		t.Fatalf("endpoint-only set: expected 200, got %d: %s", got.StatusCode, got.Body)
	}

	oc := loadOIDC(t, ctx, repo, extID)
	plain, err := cfg.DecryptClientSecret(ctx, oc)
	if err != nil {
		t.Fatalf("DecryptClientSecret: %v", err)
	}
	if string(plain) != "original-secret" {
		t.Fatalf("preserved secret = %q, want original-secret", plain)
	}
}

func TestAdminSetOIDC_RejectsNonHTTPS(t *testing.T) {
	router, _, _, token, extID := adminIssuerRig(t, []string{"admin.issuer.v1.*"})

	// Authenticated, but no X-Forwarded-Proto: https — must fail closed before
	// any secret handling.
	got := router.Dispatch(context.Background(), "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: map[string]string{"Cookie": "shadow=" + token},
		Body:    `{"issuer_id":"` + extID + `","client_id":"c","client_secret":"x"}`,
	})
	if got.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", got.StatusCode, got.Body)
	}
	if code := errBody(t, got.Body); code != "https_required" {
		t.Fatalf("error = %q, want https_required", code)
	}
}

func TestAdminSetOIDC_UnauthenticatedWithoutCookie(t *testing.T) {
	router, _, _, _, extID := adminIssuerRig(t, []string{"admin.issuer.v1.*"})

	got := router.Dispatch(context.Background(), "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: map[string]string{"X-Forwarded-Proto": "https"},
		Body:    `{"issuer_id":"` + extID + `","client_id":"c","client_secret":"x"}`,
	})
	if got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", got.StatusCode, got.Body)
	}
}

func TestAdminSetOIDC_ForbiddenWithoutGrant(t *testing.T) {
	// Authenticated user holds an unrelated grant, not admin.issuer.v1.*.
	router, _, _, token, extID := adminIssuerRig(t, []string{"auth.user.v1.Lock"})

	got := router.Dispatch(context.Background(), "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: secureHeaders(token),
		Body:    `{"issuer_id":"` + extID + `","client_id":"c","client_secret":"x"}`,
	})
	if got.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", got.StatusCode, got.Body)
	}
}

func TestAdminSetOIDC_BadRequestMissingFields(t *testing.T) {
	router, _, _, token, _ := adminIssuerRig(t, []string{"admin.issuer.v1.*"})

	got := router.Dispatch(context.Background(), "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: secureHeaders(token),
		Body:    `{"issuer_id":"ext-1"}`, // no client_id
	})
	if got.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", got.StatusCode, got.Body)
	}
}

// Pointing the OIDC config at a non-KIND_EXTERNAL issuer must surface as a 400
// client error (via ErrIssuerNotExternal → applyError), not a 500.
func TestAdminSetOIDC_NonExternalIssuerIs400(t *testing.T) {
	router, _, _, token, _ := adminIssuerRig(t, []string{"admin.issuer.v1.*"})

	got := router.Dispatch(context.Background(), "POST", "/admin/issuer/setoidc", protosource.Request{
		Headers: secureHeaders(token),
		Body:    `{"issuer_id":"issuer-self","client_id":"c","client_secret":"x"}`, // issuer-self is KIND_SELF
	})
	if got.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", got.StatusCode, got.Body)
	}
}

// loadOIDC reads the issuer's current OIDCConfig straight from the shared repo
// so secret-handling assertions inspect persisted state, not handler output.
func loadOIDC(t *testing.T, ctx context.Context, repo service.AggregateRepo, issuerID string) *issuerv1.OIDCConfig {
	t.Helper()
	agg, err := repo.Load(ctx, issuerID)
	if err != nil {
		t.Fatalf("load issuer %q: %v", issuerID, err)
	}
	iss, ok := agg.(*issuerv1.Issuer)
	if !ok {
		t.Fatalf("loaded %T, want *issuerv1.Issuer", agg)
	}
	return iss.GetOidc()
}

func errBody(t *testing.T, body string) string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unmarshal error body %q: %v", body, err)
	}
	return m["error"]
}
