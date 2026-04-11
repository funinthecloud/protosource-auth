package keyv1_test

import (
	"context"
	"testing"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
)

func TestKeyAggregateSmoke(t *testing.T) {
	ctx := context.Background()

	store := memorystore.New(0)
	repo := keyv1.NewRepository(store, protobinaryserializer.NewSerializer())

	const (
		kid     = "issuer-self:2026-04-11:EdDSA"
		actorID = "keys-resolver"
	)

	if _, err := repo.Apply(ctx, &keyv1.Generate{
		Id:             kid,
		Actor:          actorID,
		IssuerId:       "issuer-self",
		Algorithm:      "EdDSA",
		PublicJwk:      []byte(`{"kty":"OKP","crv":"Ed25519","x":"abc"}`),
		WrappedPrivate: []byte("opaque-wrapped-blob"),
		KeyProvider:    "local",
		MasterKeyRef:   "local-master",
		EffectiveAt:    1744329600,
		SigningUntil:   1744416000,
		VerifyUntil:    1744455600,
	}); err != nil {
		t.Fatalf("Apply Generate: %v", err)
	}

	agg, err := repo.Load(ctx, kid)
	if err != nil {
		t.Fatalf("Load after Generate: %v", err)
	}
	k := agg.(*keyv1.Key)
	if k.GetState() != keyv1.State_STATE_SIGNING {
		t.Errorf("State = %v, want STATE_SIGNING", k.GetState())
	}
	if k.GetAlgorithm() != "EdDSA" {
		t.Errorf("Algorithm = %q", k.GetAlgorithm())
	}
	if k.GetKeyProvider() != "local" {
		t.Errorf("KeyProvider = %q", k.GetKeyProvider())
	}

	// SIGNING → VERIFY_ONLY
	if _, err := repo.Apply(ctx, &keyv1.Retire{Id: kid, Actor: actorID}); err != nil {
		t.Fatalf("Apply Retire: %v", err)
	}
	agg, _ = repo.Load(ctx, kid)
	if state := agg.(*keyv1.Key).GetState(); state != keyv1.State_STATE_VERIFY_ONLY {
		t.Errorf("State after Retire = %v, want STATE_VERIFY_ONLY", state)
	}

	// Retiring again must fail — StateGuard.
	if _, err := repo.Apply(ctx, &keyv1.Retire{Id: kid, Actor: actorID}); err == nil {
		t.Errorf("Retire on VERIFY_ONLY key should have been rejected")
	}

	// VERIFY_ONLY → EXPIRED
	if _, err := repo.Apply(ctx, &keyv1.Expire{Id: kid, Actor: actorID}); err != nil {
		t.Fatalf("Apply Expire: %v", err)
	}
	agg, _ = repo.Load(ctx, kid)
	if state := agg.(*keyv1.Key).GetState(); state != keyv1.State_STATE_EXPIRED {
		t.Errorf("State after Expire = %v, want STATE_EXPIRED", state)
	}
}
