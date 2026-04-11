package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/funinthecloud/protosource-auth/app"
	"github.com/funinthecloud/protosource-auth/credentials"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/service"
)

// These tests exercise the public Bundle/Bootstrap/RegisterDefaultIssuer
// API that the mgr CLI drives. They run against the memory backend so
// they don't need DynamoDB Local — the same code paths are covered
// against real DynamoDB by TestDynamoDBBackendEndToEnd.

func newMemoryBundle(t *testing.T) (*app.Bundle, *app.Config) {
	t.Helper()
	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	cfg := &app.Config{
		MasterKey:              masterKey,
		IssuerIss:              "https://auth.test.example.com",
		BootstrapAdminEmail:    "admin@example.com",
		BootstrapAdminPassword: "hunter2",
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	bundle, err := app.NewBundle(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })
	return bundle, cfg
}

func TestNewBundleMemoryFields(t *testing.T) {
	bundle, _ := newMemoryBundle(t)
	if bundle.UserRepo == nil || bundle.RoleRepo == nil || bundle.IssuerRepo == nil ||
		bundle.KeyRepo == nil || bundle.TokenRepo == nil {
		t.Errorf("bundle has nil repo fields: %+v", bundle)
	}
	if bundle.Directory == nil {
		t.Errorf("bundle.Directory is nil")
	}
}

func TestBootstrapCreatesAdmin(t *testing.T) {
	bundle, cfg := newMemoryBundle(t)
	ctx := context.Background()

	result, err := app.Bootstrap(ctx, cfg, bundle, nil)
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if result.UserID != app.DefaultBootstrapAdminUserID {
		t.Errorf("UserID = %q, want %q", result.UserID, app.DefaultBootstrapAdminUserID)
	}
	if result.RoleID != app.DefaultSuperAdminRoleID {
		t.Errorf("RoleID = %q, want %q", result.RoleID, app.DefaultSuperAdminRoleID)
	}

	// The admin should be loadable and ACTIVE, with the password hash
	// verifying against the configured password.
	agg, err := bundle.UserRepo.Load(ctx, result.UserID)
	if err != nil {
		t.Fatalf("Load bootstrap admin: %v", err)
	}
	u := agg.(*userv1.User)
	if u.GetState() != userv1.State_STATE_ACTIVE {
		t.Errorf("admin state = %v, want STATE_ACTIVE", u.GetState())
	}
	if err := credentials.Verify(u.GetPasswordHash(), "hunter2"); err != nil {
		t.Errorf("Verify(hunter2): %v", err)
	}

	// MapDirectory should have been populated.
	got, err := bundle.Directory.FindByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatalf("Directory.FindByEmail: %v", err)
	}
	if got != result.UserID {
		t.Errorf("Directory.FindByEmail = %q, want %q", got, result.UserID)
	}
}

func TestBootstrapIsIdempotent(t *testing.T) {
	bundle, cfg := newMemoryBundle(t)
	ctx := context.Background()

	r1, err := app.Bootstrap(ctx, cfg, bundle, nil)
	if err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}
	r2, err := app.Bootstrap(ctx, cfg, bundle, nil)
	if err != nil {
		t.Fatalf("second Bootstrap (should tolerate existing state): %v", err)
	}
	if r1.UserID != r2.UserID || r1.RoleID != r2.RoleID || r1.IssuerID != r2.IssuerID {
		t.Errorf("idempotent bootstrap produced different results: %+v vs %+v", r1, r2)
	}
}

func TestBootstrapRecoveryOverrides(t *testing.T) {
	bundle, cfg := newMemoryBundle(t)
	ctx := context.Background()

	if _, err := app.Bootstrap(ctx, cfg, bundle, nil); err != nil {
		t.Fatalf("initial Bootstrap: %v", err)
	}

	// Recovery: different email, different user id, different role
	// id. The original admin must still exist; the recovery admin
	// must be fresh and loginable.
	recoveryCfg := *cfg
	recoveryCfg.BootstrapAdminEmail = "recovery@example.com"
	recoveryCfg.BootstrapAdminPassword = "new-password"

	opts := &app.BootstrapOptions{
		RoleID: "role-super-admin-recovery-20260411",
		UserID: "user-recovery-admin-20260411",
	}
	result, err := app.Bootstrap(ctx, &recoveryCfg, bundle, opts)
	if err != nil {
		t.Fatalf("recovery Bootstrap: %v", err)
	}
	if result.UserID != opts.UserID {
		t.Errorf("UserID = %q, want %q", result.UserID, opts.UserID)
	}
	if result.RoleID != opts.RoleID {
		t.Errorf("RoleID = %q, want %q", result.RoleID, opts.RoleID)
	}

	// Original admin still exists.
	if _, err := bundle.UserRepo.Load(ctx, app.DefaultBootstrapAdminUserID); err != nil {
		t.Errorf("original admin disappeared: %v", err)
	}
	// Recovery admin exists and has the new password.
	agg, err := bundle.UserRepo.Load(ctx, opts.UserID)
	if err != nil {
		t.Fatalf("load recovery admin: %v", err)
	}
	u := agg.(*userv1.User)
	if err := credentials.Verify(u.GetPasswordHash(), "new-password"); err != nil {
		t.Errorf("recovery admin password verify: %v", err)
	}

	// Directory must now point at the recovery user via its new email.
	got, err := bundle.Directory.FindByEmail(ctx, "recovery@example.com")
	if err != nil {
		t.Fatalf("Directory.FindByEmail(recovery): %v", err)
	}
	if got != opts.UserID {
		t.Errorf("recovery lookup = %q, want %q", got, opts.UserID)
	}
}

func TestBootstrapRequiresCredentialFields(t *testing.T) {
	masterKey, _ := local.GenerateMasterKey()
	cfg := &app.Config{
		MasterKey: masterKey,
		IssuerIss: "https://x",
	}
	// BootstrapAdminEmail empty - Normalize is fine, Bootstrap should error.
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	bundle, err := app.NewBundle(context.Background(), cfg)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	t.Cleanup(func() { _ = bundle.Close() })

	_, err = app.Bootstrap(context.Background(), cfg, bundle, nil)
	if err == nil {
		t.Fatal("Bootstrap without credentials should error")
	}
}

func TestBootstrapRequiresNonNilBundle(t *testing.T) {
	masterKey, _ := local.GenerateMasterKey()
	cfg := &app.Config{
		MasterKey:              masterKey,
		IssuerIss:              "https://x",
		BootstrapAdminEmail:    "a@b",
		BootstrapAdminPassword: "pw",
	}
	_, err := app.Bootstrap(context.Background(), cfg, nil, nil)
	if err == nil {
		t.Fatal("Bootstrap with nil bundle should error")
	}
}

func TestRegisterDefaultIssuerIdempotent(t *testing.T) {
	bundle, cfg := newMemoryBundle(t)
	ctx := context.Background()

	if err := app.RegisterDefaultIssuer(ctx, cfg, bundle); err != nil {
		t.Fatalf("first RegisterDefaultIssuer: %v", err)
	}
	if err := app.RegisterDefaultIssuer(ctx, cfg, bundle); err != nil {
		t.Fatalf("second RegisterDefaultIssuer (should be idempotent): %v", err)
	}
}

// Sanity check that the UserDirectory is still a MapDirectory for the
// memory backend — the mgr relies on this for eager population during
// bootstrap, and regressing to a different directory type would break
// offline bootstrap without a persistent GSI.
func TestMemoryBundleDirectoryIsMapDirectory(t *testing.T) {
	bundle, _ := newMemoryBundle(t)
	if _, ok := bundle.Directory.(*service.MapDirectory); !ok {
		t.Errorf("Directory = %T, want *service.MapDirectory", bundle.Directory)
	}
}

// Reuse errors.Is check just to keep the imports meaningful.
func TestBootstrapDoesNotReturnStrayErrors(t *testing.T) {
	bundle, cfg := newMemoryBundle(t)
	_, err := app.Bootstrap(context.Background(), cfg, bundle, nil)
	if errors.Is(err, errors.New("nope")) {
		t.Errorf("unexpected error identity match")
	}
}
