package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/funinthecloud/protosource/authz"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

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

// endToEndRig stands up every aggregate repo, the key resolver, and a
// Loginer + Checker pair sharing the same stores, with a frozen clock
// so token TTL and daily-key rotation are deterministic.
type endToEndRig struct {
	loginer *service.Loginer
	checker *service.Checker

	userRepo   service.AggregateRepo
	issuerRepo service.AggregateRepo
	roleRepo   service.AggregateRepo
	tokenRepo  service.AggregateRepo
	resolver   *keys.Resolver

	directory *fakeDirectory
	clock     func() time.Time
}

// fakeDirectory is an in-memory UserDirectory for tests: an email→user_id
// map populated explicitly by the test body.
type fakeDirectory struct {
	emails map[string]string
}

func (d *fakeDirectory) FindByEmail(ctx context.Context, email string) (string, error) {
	if id, ok := d.emails[email]; ok {
		return id, nil
	}
	return "", errors.New("not found")
}

func newE2ERig(t *testing.T) *endToEndRig {
	t.Helper()

	serializer := protobinaryserializer.NewSerializer()

	userStore := memorystore.New(userv1.SnapshotEveryNEvents)
	userRepo := userv1.NewRepository(userStore, serializer)

	roleStore := memorystore.New(rolev1.SnapshotEveryNEvents)
	roleRepo := rolev1.NewRepository(roleStore, serializer)

	issuerStore := memorystore.New(0)
	issuerRepo := issuerv1.NewRepository(issuerStore, serializer)

	keyStore := memorystore.New(0)
	keyRepo := keyv1.NewRepository(keyStore, serializer)

	tokenStore := memorystore.New(0)
	tokenRepo := tokenv1.NewRepository(tokenStore, serializer)

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
		keyRepo,
		provider,
		"local-master",
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
		keys.WithClock(clock),
	)

	directory := &fakeDirectory{emails: make(map[string]string)}

	loginer := service.NewLoginer(
		userRepo, issuerRepo, tokenRepo,
		directory, resolver,
		service.WithLoginerClock(clock),
	)
	checker := service.NewChecker(
		tokenRepo, userRepo, roleRepo,
		service.WithCheckerClock(clock),
	)

	return &endToEndRig{
		loginer:    loginer,
		checker:    checker,
		userRepo:   userRepo,
		issuerRepo: issuerRepo,
		roleRepo:   roleRepo,
		tokenRepo:  tokenRepo,
		resolver:   resolver,
		directory:  directory,
		clock:      clock,
	}
}

// seed builds a minimal working auth universe: one issuer, one role with
// the given function grants, one active user with the given email and
// password. Returns user id and issuer id for use in Login calls.
func (r *endToEndRig) seed(t *testing.T, email, password string, grants []string) (userID, issuerID string) {
	t.Helper()
	ctx := context.Background()

	issuerID = "issuer-self"
	if _, err := r.issuerRepo.Apply(ctx, &issuerv1.Register{
		Id:              issuerID,
		Actor:           "bootstrap",
		Iss:             "https://auth.example.com",
		DisplayName:     "Example Auth",
		Kind:            issuerv1.Kind_KIND_SELF,
		DefaultAlgorithm: ed25519signer.Algorithm,
	}); err != nil {
		t.Fatalf("seed Register issuer: %v", err)
	}

	roleID := "role-admin"
	if _, err := r.roleRepo.Apply(ctx, &rolev1.Create{
		Id:          roleID,
		Actor:       "bootstrap",
		Name:        "admin",
		Description: "test role",
	}); err != nil {
		t.Fatalf("seed Create role: %v", err)
	}
	for _, fn := range grants {
		if _, err := r.roleRepo.Apply(ctx, &rolev1.AddFunction{
			Id:    roleID,
			Actor: "bootstrap",
			Grant: &rolev1.FunctionGrant{Function: fn, GrantedAt: r.clock().Unix()},
		}); err != nil {
			t.Fatalf("seed AddFunction %q: %v", fn, err)
		}
	}

	hash, err := credentials.Hash(password)
	if err != nil {
		t.Fatalf("seed hash password: %v", err)
	}

	userID = "user-alice"
	if _, err := r.userRepo.Apply(ctx, &userv1.Create{
		Id:           userID,
		Actor:        "bootstrap",
		Email:        email,
		PasswordHash: hash,
	}); err != nil {
		t.Fatalf("seed Create user: %v", err)
	}
	if _, err := r.userRepo.Apply(ctx, &userv1.AssignRole{
		Id:    userID,
		Actor: "bootstrap",
		Grant: &userv1.RoleGrant{RoleId: roleID, AssignedAt: r.clock().Unix()},
	}); err != nil {
		t.Fatalf("seed AssignRole: %v", err)
	}

	r.directory.emails[email] = userID
	return userID, issuerID
}

func TestLoginCheckEndToEnd(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "alice@example.com", "correct horse battery staple", []string{
		"auth.user.v1.Create",
		"showcase.app.todolist.v1.*",
	})

	// Login.
	resp, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email:    "alice@example.com",
		Password: "correct horse battery staple",
		IssuerID: issuerID,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if resp.ShadowToken == "" {
		t.Errorf("empty shadow token")
	}
	if resp.JWT == "" {
		t.Errorf("empty JWT in response")
	}
	if resp.ExpiresAt <= rig.clock().Unix() {
		t.Errorf("ExpiresAt %d is not in the future relative to clock %d", resp.ExpiresAt, rig.clock().Unix())
	}

	// Verify the returned JWT actually validates against the resolver's
	// verification key — proves the sign + JWKS path is consistent.
	kid := keys.ComputeKid(issuerID, ed25519signer.Algorithm, rig.clock())
	vk, err := rig.resolver.VerificationKey(ctx, kid)
	if err != nil {
		t.Fatalf("VerificationKey: %v", err)
	}
	if _, err := vk.Verify(resp.JWT); err != nil {
		t.Errorf("JWT failed verification against its own kid: %v", err)
	}

	// Check — exact function match (allowed).
	cr, err := rig.checker.Check(ctx, service.CheckRequest{
		Token:            resp.ShadowToken,
		RequiredFunction: "auth.user.v1.Create",
	})
	if err != nil {
		t.Fatalf("Check(allowed exact): %v", err)
	}
	if cr.UserID != "user-alice" {
		t.Errorf("Check.UserID = %q", cr.UserID)
	}
	if cr.JWT != resp.JWT {
		t.Errorf("Check.JWT does not match issued JWT")
	}

	// Check — wildcard match (allowed).
	if _, err := rig.checker.Check(ctx, service.CheckRequest{
		Token:            resp.ShadowToken,
		RequiredFunction: "showcase.app.todolist.v1.Archive",
	}); err != nil {
		t.Errorf("Check(wildcard): %v", err)
	}

	// Check — function NOT granted (forbidden).
	_, err = rig.checker.Check(ctx, service.CheckRequest{
		Token:            resp.ShadowToken,
		RequiredFunction: "auth.role.v1.Delete",
	})
	if !errors.Is(err, authz.ErrForbidden) {
		t.Errorf("Check(ungranted) = %v, want ErrForbidden", err)
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "alice@example.com", "right", nil)

	_, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email:    "alice@example.com",
		Password: "wrong",
		IssuerID: issuerID,
	})
	if !errors.Is(err, service.ErrInvalidCredentials) {
		t.Errorf("Login(wrong password) = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginRejectsUnknownEmail(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "alice@example.com", "pw", nil)

	_, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email:    "bob@example.com",
		Password: "pw",
		IssuerID: issuerID,
	})
	if !errors.Is(err, service.ErrInvalidCredentials) {
		t.Errorf("Login(unknown email) = %v, want ErrInvalidCredentials", err)
	}
}

func TestLoginRejectsLockedUser(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	userID, issuerID := rig.seed(t, "alice@example.com", "pw", nil)

	if _, err := rig.userRepo.Apply(ctx, &userv1.Lock{
		Id:     userID,
		Actor:  "admin",
		Reason: "suspicious",
	}); err != nil {
		t.Fatalf("Apply Lock: %v", err)
	}

	_, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email:    "alice@example.com",
		Password: "pw",
		IssuerID: issuerID,
	})
	if !errors.Is(err, service.ErrUserNotActive) {
		t.Errorf("Login(locked) = %v, want ErrUserNotActive", err)
	}
}

func TestCheckRejectsUnknownToken(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	rig.seed(t, "alice@example.com", "pw", []string{"auth.user.v1.Create"})

	_, err := rig.checker.Check(ctx, service.CheckRequest{
		Token:            "not-a-real-token",
		RequiredFunction: "auth.user.v1.Create",
	})
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Check(unknown token) = %v, want ErrUnauthenticated", err)
	}
}

func TestCheckRejectsRevokedToken(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "alice@example.com", "pw", []string{"auth.user.v1.Create"})

	resp, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email: "alice@example.com", Password: "pw", IssuerID: issuerID,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	if _, err := rig.tokenRepo.Apply(ctx, &tokenv1.Revoke{
		Id:    resp.ShadowToken,
		Actor: "admin",
	}); err != nil {
		t.Fatalf("Apply Revoke: %v", err)
	}

	_, err = rig.checker.Check(ctx, service.CheckRequest{
		Token:            resp.ShadowToken,
		RequiredFunction: "auth.user.v1.Create",
	})
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Check(revoked) = %v, want ErrUnauthenticated", err)
	}
}

func TestCheckUsesCacheOnSecondCall(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "alice@example.com", "pw", []string{"auth.user.v1.Create"})

	resp, _ := rig.loginer.Login(ctx, service.LoginRequest{
		Email: "alice@example.com", Password: "pw", IssuerID: issuerID,
	})

	// First call populates the cache.
	if _, err := rig.checker.Check(ctx, service.CheckRequest{
		Token: resp.ShadowToken, RequiredFunction: "auth.user.v1.Create",
	}); err != nil {
		t.Fatalf("first Check: %v", err)
	}

	// Mutate the role OUT from under the cache. Because the cache has the
	// old set, the Checker should still allow the now-removed function
	// until the TTL expires. This proves the cache is actually being hit.
	if _, err := rig.roleRepo.Apply(ctx, &rolev1.RemoveFunction{
		Id:       "role-admin",
		Actor:    "admin",
		Function: "auth.user.v1.Create",
	}); err != nil {
		t.Fatalf("Apply RemoveFunction: %v", err)
	}

	if _, err := rig.checker.Check(ctx, service.CheckRequest{
		Token: resp.ShadowToken, RequiredFunction: "auth.user.v1.Create",
	}); err != nil {
		t.Errorf("Check(after RemoveFunction, within TTL): %v — cache should have masked the removal", err)
	}
}

func TestCheckRejectsExpiredToken(t *testing.T) {
	ctx := context.Background()
	rig := newE2ERig(t)
	_, issuerID := rig.seed(t, "alice@example.com", "pw", []string{"auth.user.v1.Create"})

	resp, err := rig.loginer.Login(ctx, service.LoginRequest{
		Email: "alice@example.com", Password: "pw", IssuerID: issuerID,
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	// Advance time past the token's expires_at. We can't mutate the
	// frozen clock closure from here, so we construct a fresh Checker
	// with a later clock reading against the same stores.
	laterClock := func() time.Time { return time.Unix(resp.ExpiresAt+1, 0) }
	later := service.NewChecker(
		rig.tokenRepo, rig.userRepo, rig.roleRepo,
		service.WithCheckerClock(laterClock),
	)

	_, err = later.Check(ctx, service.CheckRequest{
		Token:            resp.ShadowToken,
		RequiredFunction: "auth.user.v1.Create",
	})
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Check(expired) = %v, want ErrUnauthenticated", err)
	}
}
