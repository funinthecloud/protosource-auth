package httpauthz_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/adapters/httpstandard"
	"github.com/funinthecloud/protosource/authz"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	"github.com/funinthecloud/protosource-auth/credentials"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// authServerRig stands up an httptest.Server fronting a full
// protosource-auth service: five aggregate stores + resolver + Loginer
// + Checker + service.Service wired into a protosource.Router, wrapped
// by the httpstandard adapter.
type authServerRig struct {
	server    *httptest.Server
	directory *fakeDirectory
}

type fakeDirectory struct {
	emails map[string]string
}

func (d *fakeDirectory) FindByEmail(ctx context.Context, email string) (string, error) {
	if id, ok := d.emails[email]; ok {
		return id, nil
	}
	return "", errors.New("not found")
}

func newAuthServer(t *testing.T) *authServerRig {
	t.Helper()

	serializer := protobinaryserializer.NewSerializer()

	userRepo := userv1.NewRepository(memorystore.New(userv1.SnapshotEveryNEvents), serializer)
	roleRepo := rolev1.NewRepository(memorystore.New(rolev1.SnapshotEveryNEvents), serializer)
	issuerRepo := issuerv1.NewRepository(memorystore.New(0), serializer)
	keyRepo := keyv1.NewRepository(memorystore.New(0), serializer)
	tokenRepo := tokenv1.NewRepository(memorystore.New(0), serializer)

	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(masterKey)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	fixed := time.Date(2026, 4, 11, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }

	resolver := keys.NewResolver(
		keyRepo, provider, "local-master",
		map[string]signers.Signer{ed25519signer.Algorithm: ed25519signer.Signer{}},
		keys.WithClock(clock),
	)

	dir := &fakeDirectory{emails: make(map[string]string)}
	loginer := service.NewLoginer(userRepo, issuerRepo, tokenRepo, dir, resolver, service.WithLoginerClock(clock))
	checker := service.NewChecker(tokenRepo, userRepo, roleRepo, service.WithCheckerClock(clock))

	svc := service.NewService(loginer, checker)
	router := protosource.NewRouter(svc)

	// Use a no-op extractor: the service endpoints derive identity from
	// the JSON body, not from the adapter-level Actor.
	handler := httpstandard.WrapRouter(router, func(*http.Request) string { return "" })
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	// Seed the aggregates through the same repos directly — bypasses HTTP
	// routing for test setup, matching how the bootstrap CLI will work.
	ctx := context.Background()
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id:               "issuer-self",
		Actor:            "bootstrap",
		Iss:              "https://auth.example.com",
		DisplayName:      "Example Auth",
		Kind:             issuerv1.Kind_KIND_SELF,
		DefaultAlgorithm: ed25519signer.Algorithm,
	}); err != nil {
		t.Fatalf("seed issuer: %v", err)
	}

	if _, err := roleRepo.Apply(ctx, &rolev1.Create{
		Id: "role-admin", Actor: "bootstrap", Name: "admin",
	}); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	for _, fn := range []string{"auth.user.v1.Create", "showcase.app.todolist.v1.*"} {
		if _, err := roleRepo.Apply(ctx, &rolev1.AddFunction{
			Id:    "role-admin",
			Actor: "bootstrap",
			Grant: &rolev1.FunctionGrant{Function: fn, GrantedAt: fixed.Unix()},
		}); err != nil {
			t.Fatalf("seed AddFunction %q: %v", fn, err)
		}
	}

	hash, err := credentials.Hash("hunter2")
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.Create{
		Id: "user-alice", Actor: "bootstrap",
		Email: "alice@example.com", PasswordHash: hash,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.AssignRole{
		Id: "user-alice", Actor: "bootstrap",
		Grant: &userv1.RoleGrant{RoleId: "role-admin", AssignedAt: fixed.Unix()},
	}); err != nil {
		t.Fatalf("seed AssignRole: %v", err)
	}
	dir.emails["alice@example.com"] = "user-alice"

	return &authServerRig{server: server, directory: dir}
}

// loginOverHTTP exercises the /login endpoint as a real HTTP client
// would, returning the parsed response body.
func loginOverHTTP(t *testing.T, rig *authServerRig, email, password string) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"issuer":   "issuer-self",
	})
	resp, err := http.Post(rig.server.URL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /login status %d: %s", resp.StatusCode, dump)
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /login response: %v", err)
	}
	return out
}

// ── Tests ──

func TestHTTPLoginReturnsShadowToken(t *testing.T) {
	rig := newAuthServer(t)
	out := loginOverHTTP(t, rig, "alice@example.com", "hunter2")
	if out["shadow_token"] == "" {
		t.Errorf("no shadow_token in response")
	}
	if out["jwt"] == "" {
		t.Errorf("no jwt in response")
	}
}

func TestHTTPLoginRejectsBadPassword(t *testing.T) {
	rig := newAuthServer(t)
	body, _ := json.Marshal(map[string]string{
		"email": "alice@example.com", "password": "wrong", "issuer": "issuer-self",
	})
	resp, err := http.Post(rig.server.URL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /login (bad password) status = %d, want 401", resp.StatusCode)
	}
}

func TestAuthorizerPermitsGrantedFunction(t *testing.T) {
	rig := newAuthServer(t)
	login := loginOverHTTP(t, rig, "alice@example.com", "hunter2")
	shadow := login["shadow_token"].(string)

	auth := httpauthz.New(rig.server.URL)
	ctx, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Authorization": "Bearer " + shadow}},
		"auth.user.v1.Create",
	)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if authz.UserIDFromContext(ctx) != "user-alice" {
		t.Errorf("UserIDFromContext = %q, want user-alice", authz.UserIDFromContext(ctx))
	}
	if authz.JWTFromContext(ctx) == "" {
		t.Errorf("JWTFromContext is empty; check endpoint should forward the JWT")
	}
}

func TestAuthorizerPermitsWildcardGrant(t *testing.T) {
	rig := newAuthServer(t)
	login := loginOverHTTP(t, rig, "alice@example.com", "hunter2")
	shadow := login["shadow_token"].(string)

	auth := httpauthz.New(rig.server.URL)
	_, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Authorization": "Bearer " + shadow}},
		"showcase.app.todolist.v1.Archive",
	)
	if err != nil {
		t.Errorf("Authorize(wildcard grant): %v", err)
	}
}

func TestAuthorizerForbidsUngrantedFunction(t *testing.T) {
	rig := newAuthServer(t)
	login := loginOverHTTP(t, rig, "alice@example.com", "hunter2")
	shadow := login["shadow_token"].(string)

	auth := httpauthz.New(rig.server.URL)
	_, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Authorization": "Bearer " + shadow}},
		"auth.role.v1.Delete",
	)
	if !errors.Is(err, authz.ErrForbidden) {
		t.Errorf("Authorize(ungranted) = %v, want ErrForbidden", err)
	}
}

func TestAuthorizerUnauthenticatedWhenMissingToken(t *testing.T) {
	rig := newAuthServer(t)
	auth := httpauthz.New(rig.server.URL)
	_, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{}},
		"auth.user.v1.Create",
	)
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Authorize(no token) = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthorizerUnauthenticatedWhenTokenInvalid(t *testing.T) {
	rig := newAuthServer(t)
	auth := httpauthz.New(rig.server.URL)
	_, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Authorization": "Bearer not-a-real-token"}},
		"auth.user.v1.Create",
	)
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Authorize(bad token) = %v, want ErrUnauthenticated", err)
	}
}

func TestCookieTokenSource(t *testing.T) {
	rig := newAuthServer(t)
	login := loginOverHTTP(t, rig, "alice@example.com", "hunter2")
	shadow := login["shadow_token"].(string)

	auth := httpauthz.New(rig.server.URL, httpauthz.WithTokenSource(httpauthz.Cookie("shadow")))
	_, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Cookie": "other=x; shadow=" + shadow + "; also=y"}},
		"auth.user.v1.Create",
	)
	if err != nil {
		t.Errorf("Authorize(cookie source): %v", err)
	}
}

func TestChainedTokenSourcesFallThrough(t *testing.T) {
	rig := newAuthServer(t)
	login := loginOverHTTP(t, rig, "alice@example.com", "hunter2")
	shadow := login["shadow_token"].(string)

	// Cookie first (empty), then Authorization header.
	auth := httpauthz.New(rig.server.URL, httpauthz.WithTokenSource(
		httpauthz.Chain(httpauthz.Cookie("shadow"), httpauthz.AuthorizationHeader()),
	))
	_, err := auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Authorization": "Bearer " + shadow}},
		"auth.user.v1.Create",
	)
	if err != nil {
		t.Errorf("Authorize(chained fallthrough): %v", err)
	}
}
