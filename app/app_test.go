package app_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/app"
	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
)

// newTestServer constructs an App with an in-memory bootstrap admin
// and wraps its handler in httptest.Server, returning the base URL.
func newTestServer(t *testing.T) (server *httptest.Server, cfg *app.Config) {
	t.Helper()

	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	cfg = &app.Config{
		MasterKey:              masterKey,
		IssuerIss:              "https://auth.test.example.com",
		BootstrapAdminEmail:    "admin@example.com",
		BootstrapAdminPassword: "hunter2",
	}

	instance, err := app.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("app.Run: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	if instance.BootstrapResult == nil {
		t.Fatal("bootstrap result is nil after Run with bootstrap env")
	}
	if instance.BootstrapResult.Email != "admin@example.com" {
		t.Errorf("bootstrap email = %q", instance.BootstrapResult.Email)
	}

	server = httptest.NewServer(instance.Handler)
	t.Cleanup(server.Close)
	return server, cfg
}

func TestBinaryLoginCheckRoundTrip(t *testing.T) {
	server, _ := newTestServer(t)

	// Login over real HTTP.
	body, _ := json.Marshal(map[string]string{
		"email":    "admin@example.com",
		"password": "hunter2",
		"issuer":   "default",
	})
	resp, err := http.Post(server.URL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /login status %d: %s", resp.StatusCode, dump)
	}
	var login struct {
		ShadowToken string `json:"shadow_token"`
		JWT         string `json:"jwt"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&login); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	if login.ShadowToken == "" {
		t.Errorf("empty shadow token")
	}

	// Use httpauthz.Authorizer against the same server — the super-admin
	// role grants "*", so every function must be allowed.
	auth := httpauthz.New(server.URL)
	for _, fn := range []string{
		"auth.user.v1.Create",
		"auth.role.v1.Delete",
		"showcase.app.todolist.v1.Archive",
		"literally.anything.Here",
	} {
		ctx, err := auth.Authorize(
			context.Background(),
			protosource.Request{Headers: map[string]string{"Authorization": "Bearer " + login.ShadowToken}},
			fn,
		)
		if err != nil {
			t.Errorf("Authorize(%q): %v", fn, err)
			continue
		}
		if authz.UserIDFromContext(ctx) != "user-bootstrap-admin" {
			t.Errorf("UserIDFromContext = %q", authz.UserIDFromContext(ctx))
		}
	}
}

func TestBinaryRejectsUnknownToken(t *testing.T) {
	server, _ := newTestServer(t)

	auth := httpauthz.New(server.URL)
	_, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Authorization": "Bearer garbage"}},
		"anything",
	)
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Authorize(bad token) = %v, want ErrUnauthenticated", err)
	}
}

func TestBinaryStartsWithoutBootstrap(t *testing.T) {
	// No BOOTSTRAP_EMAIL set — the service should still start and
	// register the default issuer so Loginer has something to sign
	// against, it just won't have any users yet.
	masterKey, _ := local.GenerateMasterKey()
	cfg := &app.Config{
		MasterKey: masterKey,
		IssuerIss: "https://auth.test.example.com",
	}
	instance, err := app.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run without bootstrap: %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })
	if instance.BootstrapResult != nil {
		t.Errorf("BootstrapResult = %+v, want nil when BOOTSTRAP_EMAIL is empty", instance.BootstrapResult)
	}
	if instance.Handler == nil {
		t.Errorf("Handler is nil; service should still be usable without bootstrap")
	}
}

func TestConfigNormalizeAppliesDefaults(t *testing.T) {
	masterKey, _ := local.GenerateMasterKey()
	cfg := &app.Config{
		MasterKey: masterKey,
		IssuerIss: "https://x",
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if cfg.ListenAddr != ":8080" {
		t.Errorf("ListenAddr = %q, want :8080", cfg.ListenAddr)
	}
	if cfg.IssuerID != "default" {
		t.Errorf("IssuerID = %q, want default", cfg.IssuerID)
	}
	if cfg.TokenTTL <= 0 {
		t.Errorf("TokenTTL = %v", cfg.TokenTTL)
	}
	if cfg.BootstrapActor != "bootstrap" {
		t.Errorf("BootstrapActor = %q", cfg.BootstrapActor)
	}
}

func TestRunRequiresMasterKey(t *testing.T) {
	cfg := &app.Config{IssuerIss: "https://x"}
	_, err := app.Run(context.Background(), cfg)
	if err == nil {
		t.Errorf("Run with no MasterKey should error")
	}
}

func TestConfigNormalizeRequiresIssuerIss(t *testing.T) {
	masterKey, _ := local.GenerateMasterKey()
	cfg := &app.Config{MasterKey: masterKey}
	err := cfg.Normalize()
	if err == nil {
		t.Errorf("Normalize with no IssuerIss should error")
	}
}

func TestConfigBootstrapRequiresPasswordWhenEmailSet(t *testing.T) {
	masterKey, _ := local.GenerateMasterKey()
	cfg := &app.Config{
		MasterKey:           masterKey,
		IssuerIss:           "https://x",
		BootstrapAdminEmail: "admin@example.com",
	}
	err := cfg.Normalize()
	if err == nil {
		t.Errorf("Normalize with bootstrap email but no password should error")
	}
}

func TestLoadConfigFromEnvRoundTrip(t *testing.T) {
	masterKey, _ := local.GenerateMasterKey()
	b64 := base64.StdEncoding.EncodeToString(masterKey)

	t.Setenv(app.EnvMasterKey, b64)
	t.Setenv(app.EnvIssuerIss, "https://auth.from.env")
	t.Setenv(app.EnvListenAddr, ":9999")
	t.Setenv(app.EnvTokenTTL, "4h")

	cfg, err := app.LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("LoadConfigFromEnv: %v", err)
	}
	if cfg.IssuerIss != "https://auth.from.env" {
		t.Errorf("IssuerIss = %q", cfg.IssuerIss)
	}
	if cfg.ListenAddr != ":9999" {
		t.Errorf("ListenAddr = %q", cfg.ListenAddr)
	}
	if cfg.TokenTTL.String() != "4h0m0s" {
		t.Errorf("TokenTTL = %v", cfg.TokenTTL)
	}

	// Cleanup (t.Setenv does this automatically, but be explicit)
	_ = os.Unsetenv(app.EnvMasterKey)
}
