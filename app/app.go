package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/adapters/httpstandard"

	"github.com/funinthecloud/protosource-auth/credentials"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// App is a constructed, ready-to-serve protosource-auth instance. It
// bundles the HTTP handler with a few handles that callers (or tests)
// may want to reach into, plus a Close method that releases any
// resources acquired at [Run] time.
type App struct {
	// Handler is the http.Handler that serves the auth endpoints. Use
	// it with http.ListenAndServe, httptest.NewServer, a lambda
	// adapter, etc.
	Handler http.Handler

	// Directory is the UserDirectory the Loginer uses to translate
	// emails to user ids. For [BackendMemory] this is a
	// [service.MapDirectory] populated by bootstrap; for
	// [BackendDynamoDB] it is a GSI-backed query.
	Directory service.UserDirectory

	// Config is the normalized configuration this App was built from.
	Config *Config

	// BootstrapResult, when non-nil, describes what bootstrap created.
	BootstrapResult *BootstrapResult

	close func() error
}

// Close releases resources acquired at Run time.
func (a *App) Close() error {
	if a.close != nil {
		return a.close()
	}
	return nil
}

// BootstrapResult describes the output of a successful startup
// bootstrap. Used in logging and tests.
type BootstrapResult struct {
	IssuerID string
	RoleID   string
	UserID   string
	Email    string
}

// Run constructs the full auth service from cfg and returns an App
// ready to serve. Any nil/misconfigured cfg returns an error; a
// bootstrap failure (e.g. argon2id hashing error, store Apply
// rejection) also returns an error with nothing persisted beyond
// what the backend permits.
//
// With [BackendDynamoDB], the tables named in cfg must already exist.
// Use [EnsureTables] in tests and local dev to create them
// idempotently, or provision them via the CloudFormation template
// shipped by protosource.
func Run(ctx context.Context, cfg *Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("app: cfg must not be nil")
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}

	bundle, err := newBundle(ctx, cfg)
	if err != nil {
		return nil, err
	}

	provider, err := local.New(cfg.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("app: init key provider: %w", err)
	}

	resolver := keys.NewResolver(
		bundle.keyRepo,
		provider,
		"local-master",
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
	)

	loginer := service.NewLoginer(
		bundle.userRepo, bundle.issuerRepo, bundle.tokenRepo,
		bundle.directory, resolver,
		service.WithTokenTTL(cfg.TokenTTL),
	)
	checker := service.NewChecker(bundle.tokenRepo, bundle.userRepo, bundle.roleRepo)
	svc := service.NewService(loginer, checker)

	router := protosource.NewRouter(svc)
	handler := httpstandard.WrapRouter(router, func(*http.Request) string { return "" })

	app := &App{
		Handler:   handler,
		Directory: bundle.directory,
		Config:    cfg,
		close:     bundle.close,
	}

	if cfg.BootstrapAdminEmail != "" {
		result, err := runBootstrap(ctx, cfg, bundle)
		if err != nil {
			return nil, fmt.Errorf("app: bootstrap: %w", err)
		}
		app.BootstrapResult = result
		log.Printf(
			"bootstrap: created issuer=%q role=%q user=%q email=%q backend=%q",
			result.IssuerID, result.RoleID, result.UserID, result.Email, cfg.Backend,
		)
	} else {
		// Still register the default issuer so the Loginer has
		// something to sign against. With DynamoDB this is
		// idempotent at the Apply level — re-running Register on an
		// existing issuer fails with ErrAlreadyCreated and we
		// silently accept that.
		if _, err := bundle.issuerRepo.Apply(ctx, &issuerv1.Register{
			Id:               cfg.IssuerID,
			Actor:            cfg.BootstrapActor,
			Iss:              cfg.IssuerIss,
			DisplayName:      cfg.IssuerDisplayName,
			Kind:             issuerv1.Kind_KIND_SELF,
			DefaultAlgorithm: ed25519signer.Algorithm,
		}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
			return nil, fmt.Errorf("app: register default issuer: %w", err)
		}
		log.Printf("registered default issuer id=%q iss=%q backend=%q (no admin bootstrap)", cfg.IssuerID, cfg.IssuerIss, cfg.Backend)
	}

	return app, nil
}

// runBootstrap creates the default issuer + super-admin role + admin
// user. Returns the created ids on success. Directory implementations
// that satisfy [emailRegistrar] (notably [service.MapDirectory]) are
// populated with the admin's email; GSI-backed directories see the
// new user on the next query once the index propagates.
//
// With [BackendDynamoDB] bootstrap is not idempotent — re-running
// against a populated database fails at the first ErrAlreadyCreated.
// The intent is first-run-on-a-fresh-deployment. A future mgr CLI
// will add --force-recover for lost-admin recovery.
func runBootstrap(ctx context.Context, cfg *Config, bundle *storeBundle) (*BootstrapResult, error) {
	now := time.Now().Unix()

	if _, err := bundle.issuerRepo.Apply(ctx, &issuerv1.Register{
		Id:               cfg.IssuerID,
		Actor:            cfg.BootstrapActor,
		Iss:              cfg.IssuerIss,
		DisplayName:      cfg.IssuerDisplayName,
		Kind:             issuerv1.Kind_KIND_SELF,
		DefaultAlgorithm: ed25519signer.Algorithm,
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return nil, fmt.Errorf("register issuer: %w", err)
	}

	const (
		roleID = "role-super-admin"
		userID = "user-bootstrap-admin"
	)

	if _, err := bundle.roleRepo.Apply(ctx, &rolev1.Create{
		Id:          roleID,
		Actor:       cfg.BootstrapActor,
		Name:        "super-admin",
		Description: "bootstrap-created role granting every function",
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return nil, fmt.Errorf("create super-admin role: %w", err)
	}
	if _, err := bundle.roleRepo.Apply(ctx, &rolev1.AddFunction{
		Id:    roleID,
		Actor: cfg.BootstrapActor,
		Grant: &rolev1.FunctionGrant{Function: "*", GrantedAt: now},
	}); err != nil {
		// Tolerate "already added" by swallowing — the aggregate's
		// collection ADD is naturally idempotent on key collision.
		// Any other error is fatal.
		if !errors.Is(err, protosource.ErrAlreadyCreated) {
			return nil, fmt.Errorf("grant * to super-admin role: %w", err)
		}
	}

	hash, err := credentials.Hash(cfg.BootstrapAdminPassword)
	if err != nil {
		return nil, fmt.Errorf("hash admin password: %w", err)
	}

	if _, err := bundle.userRepo.Apply(ctx, &userv1.Create{
		Id:           userID,
		Actor:        cfg.BootstrapActor,
		Email:        cfg.BootstrapAdminEmail,
		PasswordHash: hash,
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return nil, fmt.Errorf("create admin user: %w", err)
	}
	if _, err := bundle.userRepo.Apply(ctx, &userv1.AssignRole{
		Id:    userID,
		Actor: cfg.BootstrapActor,
		Grant: &userv1.RoleGrant{RoleId: roleID, AssignedAt: now},
	}); err != nil {
		return nil, fmt.Errorf("assign super-admin to admin user: %w", err)
	}

	// Directories backed by a durable index (DynamoDB GSI) don't
	// need Add — the index will surface the new user on the next
	// query. For MapDirectory we populate eagerly so the bootstrap
	// user is immediately loginable without waiting for nothing.
	if r, ok := bundle.directory.(emailRegistrar); ok {
		r.Add(cfg.BootstrapAdminEmail, userID)
	}

	return &BootstrapResult{
		IssuerID: cfg.IssuerID,
		RoleID:   roleID,
		UserID:   userID,
		Email:    cfg.BootstrapAdminEmail,
	}, nil
}
