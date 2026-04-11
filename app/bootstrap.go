package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/credentials"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// DefaultSuperAdminRoleID is the aggregate id the bootstrap flow
// assigns to its super-admin role when no override is provided.
const DefaultSuperAdminRoleID = "role-super-admin"

// DefaultBootstrapAdminUserID is the aggregate id the bootstrap flow
// assigns to the admin user it creates when no override is provided.
const DefaultBootstrapAdminUserID = "user-bootstrap-admin"

// BootstrapOptions controls the behavior of [Bootstrap] and
// [RegisterDefaultIssuer].
type BootstrapOptions struct {
	// RoleID overrides the default super-admin role aggregate id.
	// Primarily useful for recover-admin flows that want to create a
	// second super-admin role alongside the first so existing
	// grants are preserved.
	RoleID string

	// UserID overrides the default admin user aggregate id. The
	// recover-admin flow generates a timestamped id so the new
	// admin does not collide with any existing bootstrap admin.
	UserID string
}

// BootstrapResult describes the output of a successful bootstrap.
type BootstrapResult struct {
	IssuerID string
	RoleID   string
	UserID   string
	Email    string
}

// RegisterDefaultIssuer registers the default Issuer aggregate from
// cfg on bundle.IssuerRepo, tolerating protosource.ErrAlreadyCreated
// so it is idempotent against persistent backends. The resulting
// issuer is STATE_ACTIVE and KIND_SELF with default_algorithm set to
// the ed25519 signer's Algorithm constant.
func RegisterDefaultIssuer(ctx context.Context, cfg *Config, bundle *Bundle) error {
	if bundle == nil || bundle.IssuerRepo == nil {
		return fmt.Errorf("app: RegisterDefaultIssuer requires a bundle with IssuerRepo")
	}
	_, err := bundle.IssuerRepo.Apply(ctx, &issuerv1.Register{
		Id:               cfg.IssuerID,
		Actor:            cfg.BootstrapActor,
		Iss:              cfg.IssuerIss,
		DisplayName:      cfg.IssuerDisplayName,
		Kind:             issuerv1.Kind_KIND_SELF,
		DefaultAlgorithm: ed25519signer.Algorithm,
	})
	if err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return fmt.Errorf("register default issuer: %w", err)
	}
	return nil
}

// Bootstrap creates the default Issuer, a super-admin Role granting
// "*", and an ACTIVE admin User with the configured credentials, and
// assigns the super-admin role to the user. Each step tolerates
// protosource.ErrAlreadyCreated so re-running bootstrap against a
// populated backend preserves existing state (the resulting
// BootstrapResult still describes what the nominal ids are).
//
// opts may be nil to use all defaults. Passing opts.RoleID and
// opts.UserID is how the recover-admin flow creates a distinct
// second super-admin without touching the first.
//
// cfg.BootstrapAdminEmail and cfg.BootstrapAdminPassword are
// required — Bootstrap panics via Normalize if they are missing.
// Directories that satisfy emailRegistrar are populated with the
// new email/user-id pair; durable-index directories (DynamoDB GSI)
// ignore the call and surface the new user on the next query.
func Bootstrap(ctx context.Context, cfg *Config, bundle *Bundle, opts *BootstrapOptions) (*BootstrapResult, error) {
	if cfg == nil {
		return nil, fmt.Errorf("app: Bootstrap requires a non-nil Config")
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if bundle == nil {
		return nil, fmt.Errorf("app: Bootstrap requires a non-nil Bundle")
	}
	if cfg.BootstrapAdminEmail == "" || cfg.BootstrapAdminPassword == "" {
		return nil, fmt.Errorf("app: Bootstrap requires BootstrapAdminEmail and BootstrapAdminPassword on cfg")
	}

	roleID := DefaultSuperAdminRoleID
	userID := DefaultBootstrapAdminUserID
	if opts != nil {
		if opts.RoleID != "" {
			roleID = opts.RoleID
		}
		if opts.UserID != "" {
			userID = opts.UserID
		}
	}

	now := time.Now().Unix()

	if err := RegisterDefaultIssuer(ctx, cfg, bundle); err != nil {
		return nil, err
	}

	if _, err := bundle.RoleRepo.Apply(ctx, &rolev1.Create{
		Id:          roleID,
		Actor:       cfg.BootstrapActor,
		Name:        "super-admin",
		Description: "bootstrap-created role granting every function",
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return nil, fmt.Errorf("create super-admin role: %w", err)
	}
	if _, err := bundle.RoleRepo.Apply(ctx, &rolev1.AddFunction{
		Id:    roleID,
		Actor: cfg.BootstrapActor,
		Grant: &rolev1.FunctionGrant{Function: "*", GrantedAt: now},
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		// Re-adding the same function key is a no-op on the
		// collection ADD path, so ErrAlreadyCreated never actually
		// fires here — but tolerate it for symmetry with the rest
		// of the bootstrap flow.
		return nil, fmt.Errorf("grant * to super-admin role: %w", err)
	}

	hash, err := credentials.Hash(cfg.BootstrapAdminPassword)
	if err != nil {
		return nil, fmt.Errorf("hash admin password: %w", err)
	}

	if _, err := bundle.UserRepo.Apply(ctx, &userv1.Create{
		Id:           userID,
		Actor:        cfg.BootstrapActor,
		Email:        cfg.BootstrapAdminEmail,
		PasswordHash: hash,
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return nil, fmt.Errorf("create admin user: %w", err)
	}
	if _, err := bundle.UserRepo.Apply(ctx, &userv1.AssignRole{
		Id:    userID,
		Actor: cfg.BootstrapActor,
		Grant: &userv1.RoleGrant{RoleId: roleID, AssignedAt: now},
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return nil, fmt.Errorf("assign super-admin to admin user: %w", err)
	}

	if r, ok := bundle.Directory.(emailRegistrar); ok {
		r.Add(cfg.BootstrapAdminEmail, userID)
	}

	return &BootstrapResult{
		IssuerID: cfg.IssuerID,
		RoleID:   roleID,
		UserID:   userID,
		Email:    cfg.BootstrapAdminEmail,
	}, nil
}
