package tokenv1_test

import (
	"context"
	"testing"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
)

func TestTokenAggregateSmoke(t *testing.T) {
	ctx := context.Background()

	store := memorystore.New(0)
	repo := tokenv1.NewRepository(store, protobinaryserializer.NewSerializer())

	const (
		tokenID = "opaque-abcdef0123456789"
		actorID = "loginer"
	)

	if _, err := repo.Apply(ctx, &tokenv1.Issue{
		Id:        tokenID,
		Actor:     actorID,
		UserId:    "user-alice",
		IssuerId:  "issuer-self",
		Jwt:       "eyJhbGciOiJFZERTQSJ9.e30.AAAA",
		IssuedAt:  1744329600,
		ExpiresAt: 1744365600, // +10h
	}); err != nil {
		t.Fatalf("Apply Issue: %v", err)
	}

	agg, err := repo.Load(ctx, tokenID)
	if err != nil {
		t.Fatalf("Load after Issue: %v", err)
	}
	tok := agg.(*tokenv1.Token)
	if tok.GetState() != tokenv1.State_STATE_ISSUED {
		t.Errorf("State = %v, want STATE_ISSUED", tok.GetState())
	}
	if tok.GetUserId() != "user-alice" {
		t.Errorf("UserId = %q", tok.GetUserId())
	}
	if tok.GetJwt() == "" {
		t.Errorf("Jwt is empty")
	}

	// Revoke
	if _, err := repo.Apply(ctx, &tokenv1.Revoke{Id: tokenID, Actor: actorID}); err != nil {
		t.Fatalf("Apply Revoke: %v", err)
	}
	agg, _ = repo.Load(ctx, tokenID)
	if state := agg.(*tokenv1.Token).GetState(); state != tokenv1.State_STATE_REVOKED {
		t.Errorf("State after Revoke = %v, want STATE_REVOKED", state)
	}

	// Re-revoking must be rejected.
	if _, err := repo.Apply(ctx, &tokenv1.Revoke{Id: tokenID, Actor: actorID}); err == nil {
		t.Errorf("Revoke on REVOKED token should have been rejected")
	}
}
