package issuerv1_test

import (
	"context"
	"testing"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
)

func TestIssuerAggregateSmoke(t *testing.T) {
	ctx := context.Background()

	store := memorystore.New(0)
	repo := issuerv1.NewRepository(store, protobinaryserializer.NewSerializer())

	const (
		issuerID = "issuer-self"
		actorID  = "bootstrap-admin"
	)

	if _, err := repo.Apply(ctx, &issuerv1.Register{
		Id:              issuerID,
		Actor:           actorID,
		Iss:             "https://auth.example.com",
		DisplayName:     "Example Auth",
		Kind:            issuerv1.Kind_KIND_SELF,
		DefaultAlgorithm: "EdDSA",
	}); err != nil {
		t.Fatalf("Apply Register: %v", err)
	}

	agg, err := repo.Load(ctx, issuerID)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	iss := agg.(*issuerv1.Issuer)
	if iss.GetState() != issuerv1.State_STATE_ACTIVE {
		t.Errorf("State = %v, want STATE_ACTIVE", iss.GetState())
	}
	if iss.GetKind() != issuerv1.Kind_KIND_SELF {
		t.Errorf("Kind = %v, want KIND_SELF", iss.GetKind())
	}
	if iss.GetIss() != "https://auth.example.com" {
		t.Errorf("Iss = %q", iss.GetIss())
	}
	if iss.GetDefaultAlgorithm() != "EdDSA" {
		t.Errorf("DefaultAlgorithm = %q", iss.GetDefaultAlgorithm())
	}

	if _, err := repo.Apply(ctx, &issuerv1.Rename{
		Id:          issuerID,
		Actor:       actorID,
		DisplayName: "Renamed Auth",
	}); err != nil {
		t.Fatalf("Apply Rename: %v", err)
	}

	if _, err := repo.Apply(ctx, &issuerv1.SetDefaultAlgorithm{
		Id:              issuerID,
		Actor:           actorID,
		DefaultAlgorithm: "RS256",
	}); err != nil {
		t.Fatalf("Apply SetDefaultAlgorithm: %v", err)
	}

	if _, err := repo.Apply(ctx, &issuerv1.Deactivate{Id: issuerID, Actor: actorID}); err != nil {
		t.Fatalf("Apply Deactivate: %v", err)
	}

	// Re-attempt a Rename while deactivated; StateGuard must reject it.
	if _, err := repo.Apply(ctx, &issuerv1.Rename{
		Id:          issuerID,
		Actor:       actorID,
		DisplayName: "nope",
	}); err == nil {
		t.Errorf("Rename on DEACTIVATED issuer should have been rejected")
	}

	if _, err := repo.Apply(ctx, &issuerv1.Reactivate{Id: issuerID, Actor: actorID}); err != nil {
		t.Fatalf("Apply Reactivate: %v", err)
	}

	agg, _ = repo.Load(ctx, issuerID)
	iss = agg.(*issuerv1.Issuer)
	if iss.GetState() != issuerv1.State_STATE_ACTIVE {
		t.Errorf("State after Reactivate = %v, want STATE_ACTIVE", iss.GetState())
	}
	if iss.GetDisplayName() != "Renamed Auth" {
		t.Errorf("DisplayName = %q", iss.GetDisplayName())
	}
	if iss.GetDefaultAlgorithm() != "RS256" {
		t.Errorf("DefaultAlgorithm = %q", iss.GetDefaultAlgorithm())
	}
}
