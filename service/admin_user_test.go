package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/authz/directauthz"
	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	"github.com/funinthecloud/protosource-auth/credentials"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/service"
)

// adminRig sets up an authenticated admin with admin.user.v1.* grants
// and returns a router with AdminUser + the shadow token cookie value.
func adminRig(t *testing.T) (*protosource.Router, string, *endToEndRig) {
	t.Helper()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "admin@example.com", "admin-pass", []string{
		"admin.user.v1.*",
	})

	resp, err := rig.loginer.Login(context.Background(), service.LoginRequest{
		Email:    "admin@example.com",
		Password: "admin-pass",
		IssuerID: issuerID,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	az := directauthz.New(rig.checker,
		directauthz.WithTokenSource(httpauthz.Cookie("shadow")),
	)
	admin := service.NewAdminUser(rig.userRepo, az)
	router := protosource.NewRouter(admin)

	return router, resp.ShadowToken, rig
}

func TestAdminCreateUser(t *testing.T) {
	router, token, rig := adminRig(t)
	ctx := context.Background()

	got := router.Dispatch(ctx, "POST", "/admin/user/create", protosource.Request{
		Headers: map[string]string{"Cookie": "shadow=" + token},
		Body:    `{"id":"user-new","email":"new@example.com","password":"hunter2"}`,
	})

	if got.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", got.StatusCode, got.Body)
	}

	// Verify the user was created with a proper argon2id hash.
	agg, err := rig.userRepo.Load(ctx, "user-new")
	if err != nil {
		t.Fatalf("Load user: %v", err)
	}
	user := agg.(*userv1.User)
	if user.GetEmail() != "new@example.com" {
		t.Fatalf("email = %q, want new@example.com", user.GetEmail())
	}
	if err := credentials.Verify(user.GetPasswordHash(), "hunter2"); err != nil {
		t.Fatal("password hash does not verify against plaintext")
	}
}

func TestAdminCreateUserActorDerivedFromContext(t *testing.T) {
	router, token, rig := adminRig(t)
	ctx := context.Background()

	// Send a spoofed actor in the body -- it should be ignored.
	got := router.Dispatch(ctx, "POST", "/admin/user/create", protosource.Request{
		Headers: map[string]string{"Cookie": "shadow=" + token},
		Body:    `{"id":"user-spoofed","email":"spoofed@example.com","password":"pass123","actor":"evil-spoofer"}`,
	})

	if got.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", got.StatusCode, got.Body)
	}

	// The actor should be the authenticated user, not any client-supplied value.
	agg, err := rig.userRepo.Load(ctx, "user-spoofed")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	user := agg.(*userv1.User)
	if user.GetCreateBy() != "user-alice" {
		t.Fatalf("create_by = %q, want user-alice (the authenticated admin)", user.GetCreateBy())
	}
}

func TestAdminChangePassword(t *testing.T) {
	router, token, rig := adminRig(t)
	ctx := context.Background()

	got := router.Dispatch(ctx, "POST", "/admin/user/changepassword", protosource.Request{
		Headers: map[string]string{"Cookie": "shadow=" + token},
		Body:    `{"id":"user-alice","password":"new-password"}`,
	})

	if got.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", got.StatusCode, got.Body)
	}

	// Verify the new password works.
	agg, err := rig.userRepo.Load(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	user := agg.(*userv1.User)
	if err := credentials.Verify(user.GetPasswordHash(), "new-password"); err != nil {
		t.Fatal("new password hash does not verify")
	}
}

func TestAdminUnauthenticatedWithoutCookie(t *testing.T) {
	router, _, _ := adminRig(t)

	got := router.Dispatch(context.Background(), "POST", "/admin/user/create", protosource.Request{
		Body: `{"id":"x","email":"x@x.com","password":"pass"}`,
	})

	if got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", got.StatusCode, got.Body)
	}
}

func TestAdminForbiddenWithoutGrant(t *testing.T) {
	rig := newE2ERig(t)
	// Seed a user with NO admin grants.
	_, issuerID := rig.seed(t, "reader@example.com", "reader-pass", []string{
		"auth.user.v1.Lock", // has auth grants but not admin grants
	})

	resp, err := rig.loginer.Login(context.Background(), service.LoginRequest{
		Email:    "reader@example.com",
		Password: "reader-pass",
		IssuerID: issuerID,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	az := directauthz.New(rig.checker,
		directauthz.WithTokenSource(httpauthz.Cookie("shadow")),
	)
	admin := service.NewAdminUser(rig.userRepo, az)
	router := protosource.NewRouter(admin)

	got := router.Dispatch(context.Background(), "POST", "/admin/user/create", protosource.Request{
		Headers: map[string]string{"Cookie": "shadow=" + resp.ShadowToken},
		Body:    `{"id":"x","email":"x@x.com","password":"pass"}`,
	})

	if got.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", got.StatusCode, got.Body)
	}
}

func TestAdminCreateDuplicateReturnsConflict(t *testing.T) {
	router, token, _ := adminRig(t)

	// user-alice already exists from seed.
	got := router.Dispatch(context.Background(), "POST", "/admin/user/create", protosource.Request{
		Headers: map[string]string{"Cookie": "shadow=" + token},
		Body:    `{"id":"user-alice","email":"dupe@example.com","password":"pass"}`,
	})

	if got.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", got.StatusCode, got.Body)
	}

	// Verify the error message is stable (not leaking internals).
	var body map[string]string
	if err := json.Unmarshal([]byte(got.Body), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if body["error"] != "already exists" {
		t.Fatalf("error = %q, want 'already exists'", body["error"])
	}
}

func TestAdminBadRequestMissingFields(t *testing.T) {
	router, token, _ := adminRig(t)

	got := router.Dispatch(context.Background(), "POST", "/admin/user/create", protosource.Request{
		Headers: map[string]string{"Cookie": "shadow=" + token},
		Body:    `{"id":"x"}`,
	})

	if got.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", got.StatusCode, got.Body)
	}
}
