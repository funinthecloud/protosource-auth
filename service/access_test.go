package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keys"
)

// accessRig is a minimal universe for exercising access-JWT minting,
// verification, shadow identification, and the refresh endpoint.
type accessRig struct {
	resolver   *keys.Resolver
	loginer    *Loginer
	checker    *Checker
	issuerRepo AggregateRepo
	userRepo   AggregateRepo
	tokenRepo  AggregateRepo
	roleRepo   AggregateRepo
	issuerID   string
	issuerIss  string
}

func newAccessRig(t *testing.T, clock func() time.Time) *accessRig {
	t.Helper()
	ctx := context.Background()

	resolver := newSigningResolver(t, clock)
	store := memorystore.New(0)
	ser := protobinaryserializer.NewSerializer()
	issuerRepo := issuerv1.NewRepository(store, ser)
	tokenRepo := tokenv1.NewRepository(store, ser)
	userRepo := userv1.NewRepository(store, ser)
	roleRepo := rolev1.NewRepository(store, ser)

	const issuerID, issuerIss = "default", "https://auth.example.com"
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: issuerID, Actor: "test", Iss: issuerIss,
		DisplayName: "self", Kind: issuerv1.Kind_KIND_SELF, DefaultAlgorithm: "EdDSA",
	}); err != nil {
		t.Fatalf("register self issuer: %v", err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.Create{
		Id: "user-1", Actor: "test", Email: "user1@example.com", PasswordHash: []byte("x"),
	}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	loginer := NewLoginer(userRepo, issuerRepo, tokenRepo, NewMapDirectory(), resolver,
		WithLoginerClock(clock))
	checker := NewChecker(tokenRepo, userRepo, roleRepo, WithCheckerClock(clock))

	return &accessRig{
		resolver: resolver, loginer: loginer, checker: checker,
		issuerRepo: issuerRepo, userRepo: userRepo, tokenRepo: tokenRepo, roleRepo: roleRepo,
		issuerID: issuerID, issuerIss: issuerIss,
	}
}

func TestIssueAndVerifyAccessTokenRoundTrip(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rig := newAccessRig(t, func() time.Time { return now })

	jwt, expiresAt, err := rig.loginer.IssueAccessToken(ctx, "user-1", rig.issuerID)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}
	if jwt == "" {
		t.Fatal("empty access jwt")
	}
	wantExp := now.Add(DefaultAccessTTL).Unix()
	if expiresAt != wantExp {
		t.Errorf("expiresAt = %d, want %d", expiresAt, wantExp)
	}

	claims, err := VerifyAccessToken(ctx, rig.resolver, jwt, "", now)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("sub = %q, want user-1", claims.Subject)
	}
	if claims.TokenUse != AccessTokenUse {
		t.Errorf("token_use = %q, want %q", claims.TokenUse, AccessTokenUse)
	}
	if claims.Issuer != rig.issuerIss {
		t.Errorf("iss = %q, want %q", claims.Issuer, rig.issuerIss)
	}
	if claims.Audience != rig.issuerIss { // default aud = issuer iss
		t.Errorf("aud = %q, want %q", claims.Audience, rig.issuerIss)
	}
}

// TestVerifyAccessTokenRejectsShadowJWT is the non-confusability guarantee:
// the shadow token's internal JWT (no token_use claim) must NOT pass the
// access-token verifier, so an access JWT and the shadow's embedded JWT
// can never be substituted for one another.
func TestVerifyAccessTokenRejectsShadowJWT(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rig := newAccessRig(t, func() time.Time { return now })

	// IssueForUser mints a shadow Token; LoginResponse.JWT is the shadow's
	// embedded JWT (carries no token_use).
	loginResp, err := rig.loginer.IssueForUser(ctx, "user-1", rig.issuerID)
	if err != nil {
		t.Fatalf("IssueForUser: %v", err)
	}
	if _, err := VerifyAccessToken(ctx, rig.resolver, loginResp.JWT, "", now); !errors.Is(err, ErrAccessTokenInvalid) {
		t.Fatalf("VerifyAccessToken(shadow jwt) err = %v, want ErrAccessTokenInvalid", err)
	}
}

func TestVerifyAccessTokenRejections(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rig := newAccessRig(t, func() time.Time { return now })

	jwt, expiresAt, err := rig.loginer.IssueAccessToken(ctx, "user-1", rig.issuerID)
	if err != nil {
		t.Fatalf("IssueAccessToken: %v", err)
	}

	t.Run("expired", func(t *testing.T) {
		after := time.Unix(expiresAt, 0).Add(time.Second)
		if _, err := VerifyAccessToken(ctx, rig.resolver, jwt, "", after); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatalf("err = %v, want ErrAccessTokenInvalid", err)
		}
	})
	t.Run("wrong audience", func(t *testing.T) {
		if _, err := VerifyAccessToken(ctx, rig.resolver, jwt, "https://other.example", now); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatalf("err = %v, want ErrAccessTokenInvalid", err)
		}
	})
	t.Run("matching audience ok", func(t *testing.T) {
		if _, err := VerifyAccessToken(ctx, rig.resolver, jwt, rig.issuerIss, now); err != nil {
			t.Fatalf("err = %v, want nil", err)
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := VerifyAccessToken(ctx, rig.resolver, "not.a.jwt", "", now); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatalf("err = %v, want ErrAccessTokenInvalid", err)
		}
	})
	t.Run("empty", func(t *testing.T) {
		if _, err := VerifyAccessToken(ctx, rig.resolver, "", "", now); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatalf("err = %v, want ErrAccessTokenInvalid", err)
		}
	})

	// Negative cases exercising the new fail-closed check for empty iss/aud.
	// We sign directly via the resolver (the minter always populates both).
	t.Run("empty issuer", func(t *testing.T) {
		c := AccessClaims{
			Subject:   "user-1",
			Audience:  rig.issuerIss,
			TokenUse:  AccessTokenUse,
			ExpiresAt: now.Add(time.Hour).Unix(),
			// Issuer left empty
		}
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		lk, err := rig.resolver.SigningKey(ctx, rig.issuerID, "EdDSA")
		if err != nil {
			t.Fatalf("SigningKey: %v", err)
		}
		badJWT, err := lk.Sign(payload)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := VerifyAccessToken(ctx, rig.resolver, badJWT, "", now); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatalf("err = %v, want ErrAccessTokenInvalid", err)
		}
	})
	t.Run("empty audience", func(t *testing.T) {
		c := AccessClaims{
			Issuer:    rig.issuerIss,
			Subject:   "user-1",
			TokenUse:  AccessTokenUse,
			ExpiresAt: now.Add(time.Hour).Unix(),
			// Audience left empty
		}
		payload, err := json.Marshal(c)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		lk, err := rig.resolver.SigningKey(ctx, rig.issuerID, "EdDSA")
		if err != nil {
			t.Fatalf("SigningKey: %v", err)
		}
		badJWT, err := lk.Sign(payload)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if _, err := VerifyAccessToken(ctx, rig.resolver, badJWT, "", now); !errors.Is(err, ErrAccessTokenInvalid) {
			t.Fatalf("err = %v, want ErrAccessTokenInvalid", err)
		}
	})
}

func TestCheckerIdentify(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rig := newAccessRig(t, func() time.Time { return now })

	// A live shadow token for user-1.
	loginResp, err := rig.loginer.IssueForUser(ctx, "user-1", rig.issuerID)
	if err != nil {
		t.Fatalf("IssueForUser: %v", err)
	}

	t.Run("valid shadow", func(t *testing.T) {
		userID, err := rig.checker.Identify(ctx, loginResp.ShadowToken)
		if err != nil {
			t.Fatalf("Identify: %v", err)
		}
		if userID != "user-1" {
			t.Errorf("userID = %q, want user-1", userID)
		}
	})
	t.Run("empty token", func(t *testing.T) {
		if _, err := rig.checker.Identify(ctx, ""); !errors.Is(err, authz.ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})
	t.Run("unknown token", func(t *testing.T) {
		if _, err := rig.checker.Identify(ctx, "nonexistent"); !errors.Is(err, authz.ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})
	t.Run("revoked shadow", func(t *testing.T) {
		if _, err := rig.tokenRepo.Apply(ctx, &tokenv1.Revoke{
			Id: loginResp.ShadowToken, Actor: "test",
		}); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if _, err := rig.checker.Identify(ctx, loginResp.ShadowToken); !errors.Is(err, authz.ErrUnauthenticated) {
			t.Fatalf("err = %v, want ErrUnauthenticated", err)
		}
	})
}

func TestCheckerIdentifyInactiveUser(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rig := newAccessRig(t, func() time.Time { return now })

	loginResp, err := rig.loginer.IssueForUser(ctx, "user-1", rig.issuerID)
	if err != nil {
		t.Fatalf("IssueForUser: %v", err)
	}
	if _, err := rig.userRepo.Apply(ctx, &userv1.Lock{Id: "user-1", Actor: "test", Reason: "test"}); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if _, err := rig.checker.Identify(ctx, loginResp.ShadowToken); !errors.Is(err, authz.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

// ── POST /auth/refresh ──

func newRefreshRouter(rig *accessRig) *protosource.Router {
	h := NewAccessHandler(rig.checker, rig.loginer, rig.issuerID, "shadow", "shadow_access",
		WithAccessHandlerClock(rig.loginer.clock))
	return protosource.NewRouter(h)
}

func TestAccessRefreshHappyPath(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rig := newAccessRig(t, func() time.Time { return now })
	router := newRefreshRouter(rig)

	loginResp, err := rig.loginer.IssueForUser(ctx, "user-1", rig.issuerID)
	if err != nil {
		t.Fatalf("IssueForUser: %v", err)
	}

	resp := router.Dispatch(ctx, "POST", "/auth/refresh", protosource.Request{
		Headers: map[string]string{
			"x-forwarded-proto": "https",
			"host":              "auth.example.com",
			"cookie":            "shadow=" + loginResp.ShadowToken,
		},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, resp.Body)
	}

	access := findCookie(resp.Cookies, "shadow_access")
	if access == nil {
		t.Fatalf("no access cookie; cookies=%v", resp.Cookies)
	}
	if !access.HttpOnly || !access.Secure {
		t.Errorf("access cookie missing HttpOnly/Secure: %+v", access)
	}
	// The cookie value verifies as a real access JWT for user-1.
	claims, err := VerifyAccessToken(ctx, rig.resolver, access.Value, "", now)
	if err != nil {
		t.Fatalf("verify refreshed access token: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Errorf("sub = %q, want user-1", claims.Subject)
	}

	var body map[string]int
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["expires_in"] <= 0 {
		t.Errorf("expires_in = %d, want > 0", body["expires_in"])
	}
}

func TestAccessRefreshRequiresHTTPS(t *testing.T) {
	rig := newAccessRig(t, time.Now)
	router := newRefreshRouter(rig)
	resp := router.Dispatch(context.Background(), "POST", "/auth/refresh", protosource.Request{
		Headers: map[string]string{"host": "auth.example.com", "cookie": "shadow=whatever"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestAccessRefreshMissingShadow(t *testing.T) {
	rig := newAccessRig(t, time.Now)
	router := newRefreshRouter(rig)
	resp := router.Dispatch(context.Background(), "POST", "/auth/refresh", protosource.Request{
		Headers: map[string]string{"x-forwarded-proto": "https", "host": "auth.example.com"},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}

func TestAccessRefreshRejectsRevokedShadow(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	rig := newAccessRig(t, func() time.Time { return now })
	router := newRefreshRouter(rig)

	loginResp, err := rig.loginer.IssueForUser(ctx, "user-1", rig.issuerID)
	if err != nil {
		t.Fatalf("IssueForUser: %v", err)
	}
	if _, err := rig.tokenRepo.Apply(ctx, &tokenv1.Revoke{
		Id: loginResp.ShadowToken, Actor: "test",
	}); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	resp := router.Dispatch(ctx, "POST", "/auth/refresh", protosource.Request{
		Headers: map[string]string{
			"x-forwarded-proto": "https",
			"host":              "auth.example.com",
			"cookie":            "shadow=" + loginResp.ShadowToken,
		},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", resp.StatusCode, resp.Body)
	}
}

type stubIdentifier struct {
	userID string
	err    error
}

func (s stubIdentifier) Identify(_ context.Context, _ string) (string, error) {
	return s.userID, s.err
}

type stubMinter struct{ err error }

func (s stubMinter) IssueAccessToken(_ context.Context, _, _ string) (string, int64, error) {
	return "", 0, s.err
}

// A backend failure minting the access token must return a 503 with the stable
// machine code "service_unavailable" (underscore, not a space) in both the
// JSON error and code fields.
func TestAccessRefreshUnavailableCode(t *testing.T) {
	h := NewAccessHandler(
		stubIdentifier{userID: "user-1"},
		stubMinter{err: errors.New("mint boom")},
		"default", "shadow", "shadow_access",
	)
	router := protosource.NewRouter(h)
	resp := router.Dispatch(context.Background(), "POST", "/auth/refresh", protosource.Request{
		Headers: map[string]string{
			"x-forwarded-proto": "https",
			"host":              "auth.example.com",
			"cookie":            "shadow=anything",
		},
	})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", resp.StatusCode, resp.Body)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(resp.Body), &body); err != nil {
		t.Fatalf("unmarshal body: %v", err)
	}
	if body["code"] != "service_unavailable" || body["error"] != "service_unavailable" {
		t.Errorf("body = %v, want code/error = service_unavailable", body)
	}
}
