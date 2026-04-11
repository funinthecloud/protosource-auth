package userv1_test

import (
	"context"
	"testing"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
)

// TestUserAggregateSmoke exercises the full User command set against an
// in-memory store to verify that the generated aggregate compiles, applies,
// transitions state, and replays correctly. This is a phase-2 smoke test,
// not a unit test suite — the goal is to catch codegen/proto mismatches
// early rather than enumerate every edge case.
func TestUserAggregateSmoke(t *testing.T) {
	ctx := context.Background()

	store := memorystore.New(userv1.SnapshotEveryNEvents)
	serializer := protobinaryserializer.NewSerializer()
	repo := userv1.NewRepository(store, serializer)

	const (
		userID  = "user-smoke-1"
		actorID = "bootstrap-admin"
		roleA   = "role-admin"
		roleB   = "role-auditor"
	)

	// Create
	if _, err := repo.Apply(ctx, &userv1.Create{
		Id:           userID,
		Actor:        actorID,
		Email:        "alice@example.com",
		PasswordHash: []byte("fake-argon2id-hash-bytes"),
	}); err != nil {
		t.Fatalf("Apply Create: %v", err)
	}

	agg, err := repo.Load(ctx, userID)
	if err != nil {
		t.Fatalf("Load after Create: %v", err)
	}
	u, ok := agg.(*userv1.User)
	if !ok {
		t.Fatalf("loaded aggregate is %T, want *userv1.User", agg)
	}
	if got := u.GetState(); got != userv1.State_STATE_ACTIVE {
		t.Errorf("State after Create = %v, want STATE_ACTIVE", got)
	}
	if got := u.GetEmail(); got != "alice@example.com" {
		t.Errorf("Email = %q, want %q", got, "alice@example.com")
	}
	if u.GetVersion() != 1 {
		t.Errorf("Version after Create = %d, want 1", u.GetVersion())
	}
	if u.GetCreateBy() != actorID {
		t.Errorf("CreateBy = %q, want %q", u.GetCreateBy(), actorID)
	}

	// Assign two roles via the collection-ADD path.
	for _, rid := range []string{roleA, roleB} {
		if _, err := repo.Apply(ctx, &userv1.AssignRole{
			Id:    userID,
			Actor: actorID,
			Grant: &userv1.RoleGrant{RoleId: rid, AssignedAt: 1744000000},
		}); err != nil {
			t.Fatalf("Apply AssignRole %q: %v", rid, err)
		}
	}

	agg, err = repo.Load(ctx, userID)
	if err != nil {
		t.Fatalf("Load after AssignRole: %v", err)
	}
	u = agg.(*userv1.User)
	roles := u.GetRoles()
	if len(roles) != 2 {
		t.Errorf("len(Roles) = %d, want 2 (got %v)", len(roles), roles)
	}
	for _, want := range []string{roleA, roleB} {
		if _, ok := roles[want]; !ok {
			t.Errorf("Roles missing %q (got %v)", want, roles)
		}
	}

	// Revoke one role via the collection-REMOVE path.
	if _, err := repo.Apply(ctx, &userv1.RevokeRole{
		Id:     userID,
		Actor:  actorID,
		RoleId: roleA,
	}); err != nil {
		t.Fatalf("Apply RevokeRole: %v", err)
	}

	agg, _ = repo.Load(ctx, userID)
	u = agg.(*userv1.User)
	if _, stillThere := u.GetRoles()[roleA]; stillThere {
		t.Errorf("RevokeRole did not remove %q (got %v)", roleA, u.GetRoles())
	}
	if _, still := u.GetRoles()[roleB]; !still {
		t.Errorf("RevokeRole removed the wrong role; expected %q to remain", roleB)
	}

	// Lock → Unlock state transitions.
	if _, err := repo.Apply(ctx, &userv1.Lock{
		Id:     userID,
		Actor:  actorID,
		Reason: "suspicious activity",
	}); err != nil {
		t.Fatalf("Apply Lock: %v", err)
	}
	agg, _ = repo.Load(ctx, userID)
	if state := agg.(*userv1.User).GetState(); state != userv1.State_STATE_LOCKED {
		t.Errorf("State after Lock = %v, want STATE_LOCKED", state)
	}

	// Lock from LOCKED must be rejected by the generated state guard.
	if _, err := repo.Apply(ctx, &userv1.Lock{Id: userID, Actor: actorID, Reason: "again"}); err == nil {
		t.Errorf("Lock while LOCKED should have been rejected by StateGuard")
	}

	if _, err := repo.Apply(ctx, &userv1.Unlock{Id: userID, Actor: actorID}); err != nil {
		t.Fatalf("Apply Unlock: %v", err)
	}
	agg, _ = repo.Load(ctx, userID)
	if state := agg.(*userv1.User).GetState(); state != userv1.State_STATE_ACTIVE {
		t.Errorf("State after Unlock = %v, want STATE_ACTIVE", state)
	}

	// Change password after the state transitions.
	newHash := []byte("a-different-argon2id-blob")
	if _, err := repo.Apply(ctx, &userv1.ChangePassword{
		Id:           userID,
		Actor:        actorID,
		PasswordHash: newHash,
	}); err != nil {
		t.Fatalf("Apply ChangePassword: %v", err)
	}
	agg, _ = repo.Load(ctx, userID)
	u = agg.(*userv1.User)
	if string(u.GetPasswordHash()) != string(newHash) {
		t.Errorf("PasswordHash after ChangePassword = %q, want %q", u.GetPasswordHash(), newHash)
	}

	// Delete terminates the lifecycle.
	if _, err := repo.Apply(ctx, &userv1.Delete{Id: userID, Actor: actorID}); err != nil {
		t.Fatalf("Apply Delete: %v", err)
	}
	agg, _ = repo.Load(ctx, userID)
	if state := agg.(*userv1.User).GetState(); state != userv1.State_STATE_DELETED {
		t.Errorf("State after Delete = %v, want STATE_DELETED", state)
	}
}
