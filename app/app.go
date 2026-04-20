// Package app wires the protosource-auth service from a [Config] into a
// ready-to-serve [http.Handler]. It is kept out of cmd/protosource-auth
// so the full binary can be exercised in-process from tests via
// [Run], and its [Bundle] + [Bootstrap] entry points are exposed so
// the protosource-authmgr CLI can call bootstrap/recover flows
// directly against the store without going through HTTP.
//
// See [Config] for environment variables, [Bundle] for the
// backend-agnostic repository set, and [Bootstrap] for the first-run
// admin creation flow.
package app

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/adapters/httpstandard"

	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/loginpage"
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

	// BootstrapResult, when non-nil, describes what the startup
	// bootstrap created.
	BootstrapResult *BootstrapResult

	bundle *Bundle
}

// Close releases resources acquired at Run time.
func (a *App) Close() error {
	if a == nil || a.bundle == nil {
		return nil
	}
	return a.bundle.Close()
}

// Run constructs the full auth service from cfg and returns an App
// ready to serve. Any nil/misconfigured cfg returns an error; a
// bootstrap failure (e.g. argon2id hashing error, store Apply
// rejection) also returns an error with nothing beyond what the
// backend permits committed.
//
// With [BackendDynamoDB], the tables named in cfg must already
// exist. Use [EnsureTables] in tests and local dev to create them
// idempotently, or provision them via the CloudFormation template
// shipped by protosource.
func Run(ctx context.Context, cfg *Config) (*App, error) {
	if cfg == nil {
		return nil, fmt.Errorf("app: cfg must not be nil")
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	if len(cfg.MasterKey) == 0 {
		return nil, fmt.Errorf("app: MasterKey is required (set %s)", EnvMasterKey)
	}

	bundle, err := NewBundle(ctx, cfg)
	if err != nil {
		return nil, err
	}

	provider, err := local.New(cfg.MasterKey)
	if err != nil {
		return nil, fmt.Errorf("app: init key provider: %w", err)
	}

	resolver := keys.NewResolver(
		bundle.KeyRepo,
		provider,
		"local-master",
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
	)

	loginer := service.NewLoginer(
		bundle.UserRepo, bundle.IssuerRepo, bundle.TokenRepo,
		bundle.Directory, resolver,
		service.WithTokenTTL(cfg.TokenTTL),
	)
	checker := service.NewChecker(bundle.TokenRepo, bundle.UserRepo, bundle.RoleRepo)
	svc := service.NewService(loginer, checker)

	lp := loginpage.New(cfg.IssuerID, loginer)
	router := protosource.NewRouter(svc, lp)
	handler := httpstandard.WrapRouter(router, func(*http.Request) string { return "" })

	app := &App{
		Handler:   handler,
		Directory: bundle.Directory,
		Config:    cfg,
		bundle:    bundle,
	}

	if cfg.BootstrapAdminEmail != "" {
		result, err := Bootstrap(ctx, cfg, bundle, nil)
		if err != nil {
			return nil, fmt.Errorf("app: bootstrap: %w", err)
		}
		app.BootstrapResult = result
		log.Printf(
			"bootstrap: created issuer=%q role=%q user=%q email=%q backend=%q",
			result.IssuerID, result.RoleID, result.UserID, result.Email, cfg.Backend,
		)
	} else {
		if err := RegisterDefaultIssuer(ctx, cfg, bundle); err != nil {
			return nil, fmt.Errorf("app: register default issuer: %w", err)
		}
		log.Printf("registered default issuer id=%q iss=%q backend=%q (no admin bootstrap)", cfg.IssuerID, cfg.IssuerIss, cfg.Backend)
	}

	return app, nil
}
