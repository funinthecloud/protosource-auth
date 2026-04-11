package app

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/adapters/httpstandard"
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

// App is a constructed, ready-to-serve protosource-auth instance. It
// bundles the HTTP handler with a few handles that callers (or tests)
// may want to reach into, plus a Close method that releases any
// resources acquired at [Run] time.
type App struct {
	// Handler is the http.Handler that serves the auth endpoints. Use
	// it with http.ListenAndServe, httptest.NewServer, a lambda
	// adapter, etc.
	Handler http.Handler

	// Directory is the in-memory email→user-id map populated by
	// bootstrap and by subsequent successful User.Create commands.
	// Exposed so advanced callers can register additional users at
	// runtime without going through the (not-yet-implemented)
	// user-admin HTTP flow.
	Directory *service.MapDirectory

	// Config is the normalized configuration this App was built from.
	Config *Config

	// BootstrapResult, when non-nil, describes what bootstrap created.
	BootstrapResult *BootstrapResult

	close func() error
}

// Close releases resources acquired at Run time. It is currently a
// no-op for the memorystore-backed phase 7 binary but is exposed so
// callers can idiomatically defer it regardless of backend.
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
// rejection) also returns an error with nothing persisted.
func Run(ctx context.Context, cfg *Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("app: cfg must not be nil")
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}

	serializer := protobinaryserializer.NewSerializer()

	userRepo := userv1.NewRepository(memorystore.New(userv1.SnapshotEveryNEvents), serializer)
	roleRepo := rolev1.NewRepository(memorystore.New(rolev1.SnapshotEveryNEvents), serializer)
	issuerRepo := issuerv1.NewRepository(memorystore.New(0), serializer)
	keyRepo := keyv1.NewRepository(memorystore.New(0), serializer)
	tokenRepo := tokenv1.NewRepository(memorystore.New(0), serializer)

	provider, err := local.New(cfg.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("app: init key provider: %w", err)
	}

	resolver := keys.NewResolver(
		keyRepo,
		provider,
		"local-master",
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
	)

	directory := service.NewMapDirectory()

	loginer := service.NewLoginer(
		userRepo, issuerRepo, tokenRepo,
		directory, resolver,
		service.WithTokenTTL(cfg.TokenTTL),
	)
	checker := service.NewChecker(tokenRepo, userRepo, roleRepo)
	svc := service.NewService(loginer, checker)

	router := protosource.NewRouter(svc)
	handler := httpstandard.WrapRouter(router, func(*http.Request) string { return "" })

	app := &App{
		Handler:   handler,
		Directory: directory,
		Config:    cfg,
	}

	// Optional startup bootstrap. Errors are fatal — returning an
	// error from Run means no handler is usable.
	if cfg.BootstrapAdminEmail != "" {
		result, err := runBootstrap(ctx, cfg, userRepo, roleRepo, issuerRepo, directory)
		if err != nil {
			return nil, fmt.Errorf("app: bootstrap: %w", err)
		}
		app.BootstrapResult = result
		log.Printf(
			"bootstrap: created issuer=%q role=%q user=%q email=%q",
			result.IssuerID, result.RoleID, result.UserID, result.Email,
		)
	} else {
		// Still register the default issuer so the Loginer has
		// something to sign against. Admin bootstrap is optional;
		// issuer is not.
		if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
			Id:               cfg.IssuerID,
			Actor:            cfg.BootstrapActor,
			Iss:              cfg.IssuerIss,
			DisplayName:      cfg.IssuerDisplayName,
			Kind:             issuerv1.Kind_KIND_SELF,
			DefaultAlgorithm: ed25519signer.Algorithm,
		}); err != nil {
			return nil, fmt.Errorf("app: register default issuer: %w", err)
		}
		log.Printf("registered default issuer id=%q iss=%q (no admin bootstrap)", cfg.IssuerID, cfg.IssuerIss)
	}

	return app, nil
}

// runBootstrap creates the default issuer + super-admin role + admin
// user. Returns the created ids on success.
func runBootstrap(
	ctx context.Context,
	cfg *Config,
	userRepo service.AggregateRepo,
	roleRepo service.AggregateRepo,
	issuerRepo service.AggregateRepo,
	directory *service.MapDirectory,
) (*BootstrapResult, error) {
	now := time.Now().Unix()

	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id:               cfg.IssuerID,
		Actor:            cfg.BootstrapActor,
		Iss:              cfg.IssuerIss,
		DisplayName:      cfg.IssuerDisplayName,
		Kind:             issuerv1.Kind_KIND_SELF,
		DefaultAlgorithm: ed25519signer.Algorithm,
	}); err != nil {
		return nil, fmt.Errorf("register issuer: %w", err)
	}

	const (
		roleID = "role-super-admin"
		userID = "user-bootstrap-admin"
	)

	if _, err := roleRepo.Apply(ctx, &rolev1.Create{
		Id:          roleID,
		Actor:       cfg.BootstrapActor,
		Name:        "super-admin",
		Description: "bootstrap-created role granting every function",
	}); err != nil {
		return nil, fmt.Errorf("create super-admin role: %w", err)
	}
	if _, err := roleRepo.Apply(ctx, &rolev1.AddFunction{
		Id:    roleID,
		Actor: cfg.BootstrapActor,
		Grant: &rolev1.FunctionGrant{Function: "*", GrantedAt: now},
	}); err != nil {
		return nil, fmt.Errorf("grant * to super-admin role: %w", err)
	}

	hash, err := credentials.Hash(cfg.BootstrapAdminPassword)
	if err != nil {
		return nil, fmt.Errorf("hash admin password: %w", err)
	}

	if _, err := userRepo.Apply(ctx, &userv1.Create{
		Id:           userID,
		Actor:        cfg.BootstrapActor,
		Email:        cfg.BootstrapAdminEmail,
		PasswordHash: hash,
	}); err != nil {
		return nil, fmt.Errorf("create admin user: %w", err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.AssignRole{
		Id:    userID,
		Actor: cfg.BootstrapActor,
		Grant: &userv1.RoleGrant{RoleId: roleID, AssignedAt: now},
	}); err != nil {
		return nil, fmt.Errorf("assign super-admin to admin user: %w", err)
	}

	directory.Add(cfg.BootstrapAdminEmail, userID)

	return &BootstrapResult{
		IssuerID: cfg.IssuerID,
		RoleID:   roleID,
		UserID:   userID,
		Email:    cfg.BootstrapAdminEmail,
	}, nil
}
