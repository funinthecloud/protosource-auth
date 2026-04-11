package rolev1_test

import (
	"context"
	"testing"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
)

// TestRoleAggregateSmoke exercises the full Role command set against an
// in-memory store: Create → Rename → SetDescription → AddFunction×3 →
// RemoveFunction → Delete, plus a rejected mutation after Delete.
func TestRoleAggregateSmoke(t *testing.T) {
	ctx := context.Background()

	store := memorystore.New(rolev1.SnapshotEveryNEvents)
	serializer := protobinaryserializer.NewSerializer()
	repo := rolev1.NewRepository(store, serializer)

	const (
		roleID  = "role-admin"
		actorID = "bootstrap-admin"
	)

	if _, err := repo.Apply(ctx, &rolev1.Create{
		Id:          roleID,
		Actor:       actorID,
		Name:        "Admin",
		Description: "full access",
	}); err != nil {
		t.Fatalf("Apply Create: %v", err)
	}

	agg, err := repo.Load(ctx, roleID)
	if err != nil {
		t.Fatalf("Load after Create: %v", err)
	}
	r, ok := agg.(*rolev1.Role)
	if !ok {
		t.Fatalf("loaded aggregate is %T, want *rolev1.Role", agg)
	}
	if r.GetState() != rolev1.State_STATE_ACTIVE {
		t.Errorf("State after Create = %v, want STATE_ACTIVE", r.GetState())
	}
	if r.GetName() != "Admin" {
		t.Errorf("Name = %q, want %q", r.GetName(), "Admin")
	}

	if _, err := repo.Apply(ctx, &rolev1.Rename{
		Id:    roleID,
		Actor: actorID,
		Name:  "SuperAdmin",
	}); err != nil {
		t.Fatalf("Apply Rename: %v", err)
	}
	if _, err := repo.Apply(ctx, &rolev1.SetDescription{
		Id:          roleID,
		Actor:       actorID,
		Description: "every function, everywhere",
	}); err != nil {
		t.Fatalf("Apply SetDescription: %v", err)
	}

	agg, _ = repo.Load(ctx, roleID)
	r = agg.(*rolev1.Role)
	if r.GetName() != "SuperAdmin" {
		t.Errorf("Name after Rename = %q, want %q", r.GetName(), "SuperAdmin")
	}
	if r.GetDescription() != "every function, everywhere" {
		t.Errorf("Description after SetDescription = %q", r.GetDescription())
	}

	// Add three function grants via the collection-ADD path.
	grants := []string{
		"auth.user.v1.Create",
		"auth.user.v1.Lock",
		"auth.role.v1.*",
	}
	for _, fn := range grants {
		if _, err := repo.Apply(ctx, &rolev1.AddFunction{
			Id:    roleID,
			Actor: actorID,
			Grant: &rolev1.FunctionGrant{Function: fn, GrantedAt: 1744000000},
		}); err != nil {
			t.Fatalf("Apply AddFunction %q: %v", fn, err)
		}
	}

	agg, _ = repo.Load(ctx, roleID)
	r = agg.(*rolev1.Role)
	if len(r.GetFunctions()) != 3 {
		t.Errorf("len(Functions) = %d, want 3 (got %v)", len(r.GetFunctions()), r.GetFunctions())
	}
	for _, fn := range grants {
		if _, ok := r.GetFunctions()[fn]; !ok {
			t.Errorf("Functions missing %q (got %v)", fn, r.GetFunctions())
		}
	}

	// Remove one.
	if _, err := repo.Apply(ctx, &rolev1.RemoveFunction{
		Id:       roleID,
		Actor:    actorID,
		Function: "auth.user.v1.Lock",
	}); err != nil {
		t.Fatalf("Apply RemoveFunction: %v", err)
	}

	agg, _ = repo.Load(ctx, roleID)
	r = agg.(*rolev1.Role)
	if _, still := r.GetFunctions()["auth.user.v1.Lock"]; still {
		t.Errorf("RemoveFunction did not remove entry (got %v)", r.GetFunctions())
	}
	if len(r.GetFunctions()) != 2 {
		t.Errorf("len(Functions) after remove = %d, want 2", len(r.GetFunctions()))
	}

	// Delete terminates the role.
	if _, err := repo.Apply(ctx, &rolev1.Delete{Id: roleID, Actor: actorID}); err != nil {
		t.Fatalf("Apply Delete: %v", err)
	}
	agg, _ = repo.Load(ctx, roleID)
	if state := agg.(*rolev1.Role).GetState(); state != rolev1.State_STATE_DELETED {
		t.Errorf("State after Delete = %v, want STATE_DELETED", state)
	}

	// Any mutation on a DELETED role must be rejected by the generated StateGuard.
	if _, err := repo.Apply(ctx, &rolev1.Rename{
		Id:    roleID,
		Actor: actorID,
		Name:  "ghost",
	}); err == nil {
		t.Errorf("Rename of DELETED role should have been rejected by StateGuard")
	}
}
