package service

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
)

// ── mock OIDC IdP ──

// mockIDP is a minimal external OpenID Provider for tests: it serves a
// discovery document, a JWKS with one RSA key, and a token endpoint that
// signs an ID token (RS256) for a fixed subject + email. It exercises the
// real go-oidc verification path (which our in-repo EdDSA signers do not
// cover — real IdPs like Google use RS256).
type mockIDP struct {
	server   *httptest.Server
	priv     *rsa.PrivateKey
	kid      string
	clientID string
	sub      string
	email    string
}

func newMockIDP(t *testing.T) *mockIDP {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	idp := &mockIDP{
		priv:     priv,
		kid:      "idp-test-key",
		clientID: "client-123",
		sub:      "idp-subject-789",
		email:    "alice@idp.example",
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		base := idp.server.URL
		writeJSON(w, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"jwks_uri":                              base + "/jwks",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(priv.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.PublicKey.E)).Bytes())
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": idp.kid, "alg": "RS256", "use": "sig", "n": n, "e": e,
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Assert PKCE wiring: the exchange must carry a code_verifier.
		_ = r.ParseForm()
		if r.Form.Get("code_verifier") == "" {
			http.Error(w, "missing code_verifier", http.StatusBadRequest)
			return
		}
		idToken := idp.signIDToken()
		writeJSON(w, map[string]any{
			"access_token": "mock-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})

	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

func (idp *mockIDP) signIDToken() string {
	now := time.Now()
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": idp.kid}
	payload := map[string]any{
		"iss":   idp.server.URL,
		"sub":   idp.sub,
		"aud":   idp.clientID,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Add(-time.Minute).Unix(),
		"email": idp.email,
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	sum := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, idp.priv, crypto.SHA256, sum[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ── fake identity resolver ──

type fakeResolver struct {
	userID string
	err    error
}

func (f fakeResolver) ResolveOrProvision(context.Context, FederatedIdentity, *issuerv1.OIDCConfig) (string, error) {
	return f.userID, f.err
}

// ── rig ──

type oauthRig struct {
	handler    *OAuthHandler
	router     *protosource.Router
	issuerRepo AggregateRepo
	tokenRepo  AggregateRepo
	idp        *mockIDP
}

func newOAuthRig(t *testing.T, clock func() time.Time, identity IdentityResolver) *oauthRig {
	t.Helper()
	ctx := context.Background()

	resolver := newSigningResolver(t, clock)

	store := memorystore.New(0)
	ser := protobinaryserializer.NewSerializer()
	issuerRepo := issuerv1.NewRepository(store, ser)
	tokenRepo := tokenv1.NewRepository(store, ser)
	userRepo := userv1.NewRepository(store, ser)

	// SELF issuer that signs the state cookie + minted shadow token.
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: "default", Actor: "test", Iss: "https://auth.example.com",
		DisplayName: "self", Kind: issuerv1.Kind_KIND_SELF, DefaultAlgorithm: "EdDSA",
	}); err != nil {
		t.Fatalf("register self issuer: %v", err)
	}

	// External IdP issuer with OIDC config (client secret wrapped by the
	// configurator's provider).
	idp := newMockIDP(t)
	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(masterKey)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	wrapped, err := provider.Encrypt(ctx, "local-master", []byte("idp-client-secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: "google", Actor: "test", Iss: "https://idp.example",
		Kind: issuerv1.Kind_KIND_EXTERNAL,
		Oidc: &issuerv1.OIDCConfig{
			ClientId:                 idp.clientID,
			WrappedClientSecret:      wrapped,
			ClientSecretKeyProvider:  provider.Name(),
			ClientSecretMasterKeyRef: "local-master",
			DiscoveryUrl:             idp.server.URL,
			ClaimMap:                 map[string]string{"email_at_link": "email"},
		},
	}); err != nil {
		t.Fatalf("register external issuer: %v", err)
	}

	configurator := NewOIDCConfigurator(issuerRepo, provider, "local-master")
	loginer := NewLoginer(userRepo, issuerRepo, tokenRepo, NewMapDirectory(), resolver)

	h := NewOAuthHandler(
		issuerRepo, configurator, resolver, loginer, identity,
		"default", "https://auth.example.com", "shadow",
		WithOAuthHTTPClient(idp.server.Client()),
		WithOAuthClock(clock),
	)
	router := protosource.NewRouter(h)

	return &oauthRig{handler: h, router: router, issuerRepo: issuerRepo, tokenRepo: tokenRepo, idp: idp}
}

func secureAuthorizeReq(idp, redirect string) protosource.Request {
	return protosource.Request{
		QueryParameters: map[string]string{"idp": idp, "redirect_uri": redirect},
		Headers:         map[string]string{"host": "auth.example.com", "x-forwarded-proto": "https"},
	}
}

// ── tests ──

func TestAuthorizeRedirectShape(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	ctx := context.Background()

	resp := rig.router.Dispatch(ctx, "GET", "/oauth/authorize",
		secureAuthorizeReq("google", "https://app.example.com/home"))

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", resp.StatusCode, resp.Body)
	}
	loc := resp.Headers["Location"]
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location %q: %v", loc, err)
	}
	if got, want := u.Scheme+"://"+u.Host+u.Path, rig.idp.server.URL+"/authorize"; got != want {
		t.Errorf("authorize endpoint = %q, want %q", got, want)
	}
	q := u.Query()
	if q.Get("client_id") != rig.idp.clientID {
		t.Errorf("client_id = %q", q.Get("client_id"))
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge missing")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q", q.Get("code_challenge_method"))
	}
	if q.Get("state") == "" {
		t.Error("state missing")
	}
	if q.Get("scope") != "openid email profile" {
		t.Errorf("scope = %q", q.Get("scope"))
	}
	if q.Get("redirect_uri") != "https://auth.example.com/oauth/callback" {
		t.Errorf("redirect_uri = %q", q.Get("redirect_uri"))
	}
	sc := resp.Headers["Set-Cookie"]
	if !strings.HasPrefix(sc, "shadow_oauth_state=") {
		t.Errorf("Set-Cookie = %q, want state cookie", sc)
	}
	if !strings.Contains(sc, "HttpOnly") || !strings.Contains(sc, "Secure") {
		t.Errorf("state cookie missing HttpOnly/Secure: %q", sc)
	}
}

func TestAuthorizeRejectsPlainHTTP(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	req := protosource.Request{
		QueryParameters: map[string]string{"idp": "google"},
		Headers:         map[string]string{"host": "auth.example.com"}, // no x-forwarded-proto
	}
	resp := rig.router.Dispatch(context.Background(), "GET", "/oauth/authorize", req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAuthorizeRejectsForeignRedirect(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	resp := rig.router.Dispatch(context.Background(), "GET", "/oauth/authorize",
		secureAuthorizeReq("google", "https://evil.test/phish"))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for foreign redirect", resp.StatusCode)
	}
}

// driveAuthorize runs authorize and returns the state nonce + the
// "name=value" cookie pair to replay on the callback.
func driveAuthorize(t *testing.T, rig *oauthRig) (state, cookiePair string) {
	t.Helper()
	resp := rig.router.Dispatch(context.Background(), "GET", "/oauth/authorize",
		secureAuthorizeReq("google", "https://app.example.com/home"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d: %s", resp.StatusCode, resp.Body)
	}
	u, _ := url.Parse(resp.Headers["Location"])
	state = u.Query().Get("state")
	cookiePair = strings.SplitN(resp.Headers["Set-Cookie"], ";", 2)[0]
	return state, cookiePair
}

// findCookie returns the first cookie with the given name, or nil.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c != nil && c.Name == name {
			return c
		}
	}
	return nil
}

func TestCallbackHappyPathSetsShadowCookie(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	ctx := context.Background()

	state, cookiePair := driveAuthorize(t, rig)

	resp := rig.router.Dispatch(ctx, "GET", "/oauth/callback", protosource.Request{
		QueryParameters: map[string]string{"code": "auth-code", "state": state},
		Headers: map[string]string{
			"host":              "auth.example.com",
			"x-forwarded-proto": "https",
			"cookie":            cookiePair,
		},
	})

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("callback status = %d, want 302; body=%s", resp.StatusCode, resp.Body)
	}
	if loc := resp.Headers["Location"]; loc != "https://app.example.com/home" {
		t.Errorf("Location = %q, want original redirect_uri", loc)
	}
	// Multi-cookie response (protosource v0.8.0): shadow + access set,
	// single-use state cookie cleared, all in one 302.
	shadowCookie := findCookie(resp.Cookies, "shadow")
	if shadowCookie == nil {
		t.Fatalf("no shadow cookie in response; cookies=%v", resp.Cookies)
	}
	if !shadowCookie.HttpOnly || !shadowCookie.Secure {
		t.Errorf("shadow cookie missing HttpOnly/Secure: %+v", shadowCookie)
	}
	accessCookie := findCookie(resp.Cookies, "shadow_access")
	if accessCookie == nil {
		t.Fatalf("no access cookie in response; cookies=%v", resp.Cookies)
	}
	if !accessCookie.HttpOnly || !accessCookie.Secure {
		t.Errorf("access cookie missing HttpOnly/Secure: %+v", accessCookie)
	}
	if accessCookie.Value == "" {
		t.Errorf("access cookie has empty value")
	}
	if stateCookie := findCookie(resp.Cookies, "shadow_oauth_state"); stateCookie == nil || stateCookie.MaxAge >= 0 {
		t.Errorf("state cookie not actively cleared: %+v", stateCookie)
	}

	// The shadow token must dereference to an issued Token for user-123.
	token := shadowCookie.Value
	agg, err := rig.tokenRepo.Load(ctx, token)
	if err != nil {
		t.Fatalf("load minted token: %v", err)
	}
	tok := agg.(*tokenv1.Token)
	if tok.GetUserId() != "user-123" {
		t.Errorf("token user = %q, want user-123", tok.GetUserId())
	}
	if tok.GetState() != tokenv1.State_STATE_ISSUED {
		t.Errorf("token state = %v, want ISSUED", tok.GetState())
	}
}

func TestCallbackJITRejectedIs403(t *testing.T) {
	now := time.Now().UTC()
	// RejectAllResolver always rejects after a successful IdP verification.
	rig := newOAuthRig(t, func() time.Time { return now }, RejectAllResolver{})
	state, cookiePair := driveAuthorize(t, rig)

	resp := rig.router.Dispatch(context.Background(), "GET", "/oauth/callback", protosource.Request{
		QueryParameters: map[string]string{"code": "auth-code", "state": state},
		Headers: map[string]string{
			"host": "auth.example.com", "x-forwarded-proto": "https", "cookie": cookiePair,
		},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for JIT-rejected identity; body=%s", resp.StatusCode, resp.Body)
	}
}

func TestCallbackTamperedStateRejected(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	state, cookiePair := driveAuthorize(t, rig)

	// Corrupt a character in the payload segment so the signature no longer
	// verifies. (Flipping the final signature char is unreliable: its low
	// base64 bits are insignificant for a 64-byte EdDSA signature.)
	name, jwt, _ := strings.Cut(cookiePair, "=")
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected jwt shape: %d segments", len(parts))
	}
	pb := []byte(parts[1])
	if pb[0] == 'e' {
		pb[0] = 'f'
	} else {
		pb[0] = 'e'
	}
	tampered := name + "=" + parts[0] + "." + string(pb) + "." + parts[2]

	resp := rig.router.Dispatch(context.Background(), "GET", "/oauth/callback", protosource.Request{
		QueryParameters: map[string]string{"code": "auth-code", "state": state},
		Headers: map[string]string{
			"host": "auth.example.com", "x-forwarded-proto": "https", "cookie": tampered,
		},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for tampered state", resp.StatusCode)
	}
}

func TestCallbackExpiredStateRejected(t *testing.T) {
	cur := time.Now().UTC()
	clock := func() time.Time { return cur }
	rig := newOAuthRig(t, clock, fakeResolver{userID: "user-123"})

	state, cookiePair := driveAuthorize(t, rig)

	// Advance past the 10-minute state TTL before the callback arrives.
	cur = cur.Add(11 * time.Minute)

	resp := rig.router.Dispatch(context.Background(), "GET", "/oauth/callback", protosource.Request{
		QueryParameters: map[string]string{"code": "auth-code", "state": state},
		Headers: map[string]string{
			"host": "auth.example.com", "x-forwarded-proto": "https", "cookie": cookiePair,
		},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for expired state", resp.StatusCode)
	}
}

func TestCallbackMissingStateCookieRejected(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	state, _ := driveAuthorize(t, rig)

	resp := rig.router.Dispatch(context.Background(), "GET", "/oauth/callback", protosource.Request{
		QueryParameters: map[string]string{"code": "auth-code", "state": state},
		Headers: map[string]string{
			"host": "auth.example.com", "x-forwarded-proto": "https", // no cookie
		},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for missing state cookie", resp.StatusCode)
	}
}

// TestIssuerBaseFromDiscoveryURL covers the normalization that lets operators
// paste either the IdP issuer base or the full discovery-document URL.
func TestIssuerBaseFromDiscoveryURL(t *testing.T) {
	for _, tc := range []struct {
		in, want string
	}{
		{"https://idp.example.com", "https://idp.example.com"},
		{"https://idp.example.com/", "https://idp.example.com"},
		{"https://idp.example.com/.well-known/openid-configuration", "https://idp.example.com"},
		{"https://idp.example.com/.well-known/openid-configuration/", "https://idp.example.com"},
		{"https://idp.example.com/tenant/.well-known/openid-configuration", "https://idp.example.com/tenant"},
		// Not a discovery suffix — left untouched.
		{"https://idp.example.com/oidc", "https://idp.example.com/oidc"},
	} {
		if got := issuerBaseFromDiscoveryURL(tc.in); got != tc.want {
			t.Errorf("issuerBaseFromDiscoveryURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestBuildOIDCMetaDiscoveryAcceptsWellKnownSuffix verifies buildOIDCMeta
// resolves the IdP endpoints whether discovery_url is the issuer base or the
// full /.well-known/openid-configuration URL (the form the admin UI suggests).
func TestBuildOIDCMetaDiscoveryAcceptsWellKnownSuffix(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	ctx := context.Background()

	for _, du := range []string{
		rig.idp.server.URL,
		rig.idp.server.URL + "/.well-known/openid-configuration",
	} {
		m, err := rig.handler.buildOIDCMeta(ctx, &issuerv1.OIDCConfig{
			ClientId:     rig.idp.clientID,
			DiscoveryUrl: du,
		})
		if err != nil {
			t.Fatalf("buildOIDCMeta(%q): %v", du, err)
		}
		if want := rig.idp.server.URL + "/authorize"; m.authURL != want {
			t.Errorf("discovery_url %q: authURL = %q, want %q", du, m.authURL, want)
		}
		if want := rig.idp.server.URL + "/token"; m.tokenURL != want {
			t.Errorf("discovery_url %q: tokenURL = %q, want %q", du, m.tokenURL, want)
		}
	}
}

// TestBuildOIDCMetaPinnedRequiresAllEndpoints verifies pinned mode (no
// discovery_url) fails closed when any of authorization_endpoint,
// token_endpoint, or jwks_uri is missing, and succeeds when all are present.
func TestBuildOIDCMetaPinnedRequiresAllEndpoints(t *testing.T) {
	now := time.Now().UTC()
	rig := newOAuthRig(t, func() time.Time { return now }, fakeResolver{userID: "user-123"})
	ctx := context.Background()

	full := &issuerv1.OIDCConfig{
		ClientId:              "client-x",
		AuthorizationEndpoint: "https://idp.example/authorize",
		TokenEndpoint:         "https://idp.example/token",
		JwksUri:               "https://idp.example/jwks",
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*issuerv1.OIDCConfig)
		missing string
	}{
		{"missing authorization_endpoint", func(c *issuerv1.OIDCConfig) { c.AuthorizationEndpoint = "" }, "authorization_endpoint"},
		{"missing token_endpoint", func(c *issuerv1.OIDCConfig) { c.TokenEndpoint = "" }, "token_endpoint"},
		{"missing jwks_uri", func(c *issuerv1.OIDCConfig) { c.JwksUri = "" }, "jwks_uri"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oc := &issuerv1.OIDCConfig{
				ClientId: full.ClientId, AuthorizationEndpoint: full.AuthorizationEndpoint,
				TokenEndpoint: full.TokenEndpoint, JwksUri: full.JwksUri,
			}
			tc.mutate(oc)
			_, err := rig.handler.buildOIDCMeta(ctx, oc)
			if err == nil {
				t.Fatalf("buildOIDCMeta with %s should error", tc.name)
			}
			if !strings.Contains(err.Error(), tc.missing) {
				t.Errorf("error %q should name %q", err, tc.missing)
			}
		})
	}

	// All endpoints present → builds without error (RemoteKeySet is lazy).
	m, err := rig.handler.buildOIDCMeta(ctx, full)
	if err != nil {
		t.Fatalf("buildOIDCMeta(full pinned): %v", err)
	}
	if m.authURL != full.AuthorizationEndpoint || m.tokenURL != full.TokenEndpoint {
		t.Errorf("pinned meta = {%q,%q}, want {%q,%q}", m.authURL, m.tokenURL, full.AuthorizationEndpoint, full.TokenEndpoint)
	}
}
