package loginpage

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	"github.com/funinthecloud/protosource-auth/credentials"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// testEnv is a fully wired in-memory auth stack for login tests.
type testEnv struct {
	page *Page
}

func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()
	serializer := protobinaryserializer.NewSerializer()

	userRepo := userv1.NewRepository(memorystore.New(0), serializer)
	issuerRepo := issuerv1.NewRepository(memorystore.New(0), serializer)
	tokenRepo := tokenv1.NewRepository(memorystore.New(0), serializer)
	keyRepo := keyv1.NewRepository(memorystore.New(0), serializer)

	// Create an active user with known credentials.
	hash, err := credentials.Hash("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.Create{
		Id: "user-1", Actor: "test",
		Email: "test@example.com", PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}

	// Create an active SELF issuer.
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: "default", Actor: "test",
		Iss: "https://test.example.com", DisplayName: "test",
		Kind: issuerv1.Kind_KIND_SELF, DefaultAlgorithm: ed25519signer.Algorithm,
	}); err != nil {
		t.Fatal(err)
	}

	// Directory: map email -> user id.
	dir := service.NewMapDirectory()
	dir.Add("test@example.com", "user-1")

	// Key provider + resolver.
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	provider, err := local.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := keys.NewResolver(keyRepo, provider, "test-master", map[string]signers.Signer{
		ed25519signer.Algorithm: ed25519signer.Signer{},
	})

	loginer := service.NewLoginer(userRepo, issuerRepo, tokenRepo, dir, resolver)
	page := New("default", loginer)

	return &testEnv{page: page}
}

// -- parentDomain tests --

func TestParentDomain(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"auth.drhayt.com", ".drhayt.com"},
		{"drhayt.com", ".drhayt.com"},
		{"sub.auth.drhayt.com", ".drhayt.com"},
		{"auth.example.co.uk", ".example.co.uk"},
		{"example.co.uk", ".example.co.uk"},
		{"localhost:8080", ""},
		{"localhost", ""},
		{"127.0.0.1:8080", ""},
		{"127.0.0.1", ""},
		{"[::1]:8080", ""},
		{"[::1]", ""},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := parentDomain(tt.host)
			if got != tt.want {
				t.Errorf("parentDomain(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// -- handlePage tests --

func TestHandlePage(t *testing.T) {
	p := &Page{issuerID: "test-issuer"} // loginer not needed for GET
	resp := p.handlePage(context.Background(), protosource.Request{})

	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Headers["Content-Type"]; ct != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", ct)
	}
	if !strings.Contains(resp.Body, "Sign In") {
		t.Error("response body missing form title")
	}
}

// -- isSecure tests --

func TestIsSecure(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"https lowercase", map[string]string{"x-forwarded-proto": "https"}, true},
		{"https titlecase", map[string]string{"X-Forwarded-Proto": "https"}, true},
		{"https uppercase", map[string]string{"x-forwarded-proto": "HTTPS"}, true},
		{"comma separated https first", map[string]string{"x-forwarded-proto": "https,http"}, true},
		{"comma separated with spaces", map[string]string{"x-forwarded-proto": "https , http"}, true},
		{"comma separated http first", map[string]string{"x-forwarded-proto": "http,https"}, false},
		{"http", map[string]string{"x-forwarded-proto": "http"}, false},
		{"missing", map[string]string{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := protosource.Request{Headers: tt.headers}
			if got := isSecure(req); got != tt.want {
				t.Errorf("isSecure() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -- isSameOrigin tests --

func TestIsSameOrigin(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		origin  string
		referer string
		want    bool
	}{
		{"same host origin", "auth.drhayt.com", "https://auth.drhayt.com", "", true},
		{"sibling subdomain origin", "auth.drhayt.com", "https://todoapp.drhayt.com", "", true},
		{"bare domain origin", "auth.drhayt.com", "https://drhayt.com", "", true},
		{"cross-domain origin", "auth.drhayt.com", "https://evil.com", "", false},
		{"no origin uses referer", "auth.drhayt.com", "", "https://todoapp.drhayt.com/page", true},
		{"cross-domain referer", "auth.drhayt.com", "", "https://evil.com/page", false},
		{"no origin or referer", "auth.drhayt.com", "", "", false},
		{"co.uk same domain", "auth.example.co.uk", "https://app.example.co.uk", "", true},
		{"co.uk cross domain", "auth.example.co.uk", "https://other.co.uk", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{"host": tt.host}
			if tt.origin != "" {
				headers["origin"] = tt.origin
			}
			if tt.referer != "" {
				headers["referer"] = tt.referer
			}
			req := protosource.Request{Headers: headers}
			if got := isSameOrigin(req); got != tt.want {
				t.Errorf("isSameOrigin() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -- New nil panic test --

func TestNewPanicsOnNilLoginer(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic, got none")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "loginer must not be nil") {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	New("issuer", nil)
}

// -- handleLogin tests --

func secureHeaders(host string) map[string]string {
	return map[string]string{
		"host":              host,
		"x-forwarded-proto": "https",
		"origin":            "https://" + host,
		"Content-Type":      "application/json",
	}
}

func TestHandleLoginRequiresHTTPS(t *testing.T) {
	env := newTestEnv(t)
	resp := env.page.handleLogin(context.Background(), protosource.Request{
		Headers: map[string]string{"host": "auth.drhayt.com"},
		Body:    `{"email":"test@example.com","password":"testpass"}`,
	})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "HTTPS is required") {
		t.Errorf("body = %q, want HTTPS error", resp.Body)
	}
}

func TestHandleLoginRejectsCrossOrigin(t *testing.T) {
	env := newTestEnv(t)
	resp := env.page.handleLogin(context.Background(), protosource.Request{
		Headers: map[string]string{
			"host":              "auth.drhayt.com",
			"x-forwarded-proto": "https",
			"origin":            "https://evil.com",
		},
		Body: `{"email":"test@example.com","password":"testpass"}`,
	})
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	if !strings.Contains(resp.Body, "cross-origin") {
		t.Errorf("body = %q, want cross-origin error", resp.Body)
	}
}

func TestHandleLoginBadBody(t *testing.T) {
	env := newTestEnv(t)
	tests := []struct {
		name    string
		body    string
		wantMsg string
	}{
		{"invalid json", `{bad`, "invalid request body"},
		{"missing email", `{"password":"x"}`, "email and password are required"},
		{"missing password", `{"email":"x"}`, "email and password are required"},
		{"empty fields", `{"email":"","password":""}`, "email and password are required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := env.page.handleLogin(context.Background(), protosource.Request{
				Headers: secureHeaders("auth.drhayt.com"),
				Body:    tt.body,
			})
			if resp.StatusCode != 400 {
				t.Errorf("status = %d, want 400", resp.StatusCode)
			}
			if !strings.Contains(resp.Body, tt.wantMsg) {
				t.Errorf("body = %q, want %q", resp.Body, tt.wantMsg)
			}
		})
	}
}

func TestHandleLoginInvalidCredentials(t *testing.T) {
	env := newTestEnv(t)
	resp := env.page.handleLogin(context.Background(), protosource.Request{
		Headers: secureHeaders("auth.drhayt.com"),
		Body:    `{"email":"test@example.com","password":"wrong"}`,
	})
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestHandleLoginSuccess(t *testing.T) {
	env := newTestEnv(t)

	tests := []struct {
		name       string
		host       string
		wantDomain string // http.Cookie strips leading dot per RFC 6265
	}{
		{"subdomain host", "auth.drhayt.com", "drhayt.com"},
		{"bare domain", "drhayt.com", "drhayt.com"},
		{"co.uk domain", "auth.example.co.uk", "example.co.uk"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := env.page.handleLogin(context.Background(), protosource.Request{
				Headers: secureHeaders(tt.host),
				Body:    `{"email":"test@example.com","password":"testpass"}`,
			})
			if resp.StatusCode != 200 {
				t.Fatalf("status = %d, want 200; body = %s", resp.StatusCode, resp.Body)
			}

			// Verify response body.
			var body map[string]bool
			if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
				t.Fatalf("unmarshal body: %v", err)
			}
			if !body["ok"] {
				t.Error("body[ok] = false")
			}

			// Verify Set-Cookie header.
			cookie := resp.Headers["Set-Cookie"]
			if cookie == "" {
				t.Fatal("missing Set-Cookie header")
			}
			if !strings.Contains(cookie, "shadow=") {
				t.Errorf("cookie missing shadow= prefix: %s", cookie)
			}
			if !strings.Contains(cookie, "HttpOnly") {
				t.Errorf("cookie missing HttpOnly: %s", cookie)
			}
			if !strings.Contains(cookie, "Secure") {
				t.Errorf("cookie missing Secure: %s", cookie)
			}
			if !strings.Contains(cookie, "SameSite=Lax") {
				t.Errorf("cookie missing SameSite=Lax: %s", cookie)
			}
			if !strings.Contains(cookie, "Max-Age=") {
				t.Errorf("cookie missing Max-Age: %s", cookie)
			}
			wantDomain := "Domain=" + tt.wantDomain
			if !strings.Contains(cookie, wantDomain) {
				t.Errorf("cookie missing %s: %s", wantDomain, cookie)
			}
		})
	}
}

func TestHandleLoginExpiredToken(t *testing.T) {
	ctx := context.Background()
	serializer := protobinaryserializer.NewSerializer()

	userRepo := userv1.NewRepository(memorystore.New(0), serializer)
	issuerRepo := issuerv1.NewRepository(memorystore.New(0), serializer)
	tokenRepo := tokenv1.NewRepository(memorystore.New(0), serializer)
	keyRepo := keyv1.NewRepository(memorystore.New(0), serializer)

	hash, err := credentials.Hash("testpass")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.Create{
		Id: "user-1", Actor: "test",
		Email: "test@example.com", PasswordHash: hash,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: "default", Actor: "test",
		Iss: "https://test.example.com", DisplayName: "test",
		Kind: issuerv1.Kind_KIND_SELF, DefaultAlgorithm: ed25519signer.Algorithm,
	}); err != nil {
		t.Fatal(err)
	}
	dir := service.NewMapDirectory()
	dir.Add("test@example.com", "user-1")

	masterKey := make([]byte, 32)
	provider, err := local.New(masterKey)
	if err != nil {
		t.Fatal(err)
	}
	resolver := keys.NewResolver(keyRepo, provider, "test-master", map[string]signers.Signer{
		ed25519signer.Algorithm: ed25519signer.Signer{},
	})

	// Use a clock that returns a time in the past so the token is
	// already expired by the time handleLogin checks Max-Age.
	pastClock := func() time.Time { return time.Now().Add(-24 * time.Hour) }
	loginer := service.NewLoginer(userRepo, issuerRepo, tokenRepo, dir, resolver,
		service.WithLoginerClock(pastClock),
		service.WithTokenTTL(1*time.Hour),
	)
	page := New("default", loginer)

	resp := page.handleLogin(ctx, protosource.Request{
		Headers: secureHeaders("auth.drhayt.com"),
		Body:    `{"email":"test@example.com","password":"testpass"}`,
	})
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503; body = %s", resp.StatusCode, resp.Body)
	}
	if !strings.Contains(resp.Body, "token already expired") {
		t.Errorf("body = %q, want expired error", resp.Body)
	}
}
