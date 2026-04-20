package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/service"
)

func TestWhoamiReturnsUserContext(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "alice@example.com", "s3cret!", []string{"*"})

	resp, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email:    "alice@example.com",
		Password: "s3cret!",
		IssuerID: issuerID,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	whoami := service.NewWhoami(rig.tokenRepo, rig.userRepo,
		service.WithWhoamiClock(rig.clock),
	)

	req := protosource.Request{
		Headers: map[string]string{
			"Cookie": "shadow=" + resp.ShadowToken,
		},
	}

	router := protosource.NewRouter(whoami)
	got := router.Dispatch(ctx, "GET", "/whoami", req)

	if got.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", got.StatusCode, got.Body)
	}

	var body struct {
		UserID string                     `json:"user_id"`
		Email  string                     `json:"email"`
		Roles  map[string]json.RawMessage `json:"roles"`
	}
	if err := json.Unmarshal([]byte(got.Body), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.UserID != "user-alice" {
		t.Fatalf("expected user_id=user-alice, got %q", body.UserID)
	}
	if body.Email != "alice@example.com" {
		t.Fatalf("expected email=alice@example.com, got %q", body.Email)
	}
	if len(body.Roles) == 0 {
		t.Fatal("expected at least one role")
	}
}

func TestWhoamiNoCookie(t *testing.T) {
	rig := newE2ERig(t)
	whoami := service.NewWhoami(rig.tokenRepo, rig.userRepo)

	router := protosource.NewRouter(whoami)
	got := router.Dispatch(context.Background(), "GET", "/whoami", protosource.Request{})

	if got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", got.StatusCode)
	}
}

func TestWhoamiInvalidToken(t *testing.T) {
	rig := newE2ERig(t)
	whoami := service.NewWhoami(rig.tokenRepo, rig.userRepo)

	req := protosource.Request{
		Headers: map[string]string{
			"Cookie": "shadow=bogus-token-id",
		},
	}
	router := protosource.NewRouter(whoami)
	got := router.Dispatch(context.Background(), "GET", "/whoami", req)

	if got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", got.StatusCode)
	}
}
