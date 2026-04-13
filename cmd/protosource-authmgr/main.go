// Command protosource-authmgr is the operational CLI for
// protosource-auth. It talks to the backing store directly via the
// protosource aggregate Repository pattern — no HTTP round-trips to a
// running auth service, so it works when the service is down, before
// the service has ever run, or when the last admin has been lost.
//
// Subcommands:
//
//	ensure-tables    Create the DynamoDB tables if they do not exist
//	bootstrap        Create a default issuer + super-admin role + admin user
//	recover-admin    Create a fresh super-admin role + admin user alongside
//	                 any existing ones, for lost-admin recovery
//
// All commands read the same PROTOSOURCE_AUTH_* environment variables
// that the main service binary uses. Bootstrap and recover-admin
// additionally require PROTOSOURCE_AUTH_SEED_SECRET to be set (value
// not checked in phase 9 — just gates against accidental invocation).
// Phase 10 will wire this up to KMS / Secrets Manager.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/funinthecloud/protosource/stores/dynamodbstore"

	"github.com/funinthecloud/protosource-auth/app"
)

// EnvSeedSecret gates the bootstrap and recover-admin subcommands.
// Phase 9 just checks that it is non-empty; phase 10 will fetch it
// from KMS/Secrets Manager and verify against a stored digest.
const EnvSeedSecret = "PROTOSOURCE_AUTH_SEED_SECRET"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "ensure-tables":
		if err := runEnsureTables(ctx, args); err != nil {
			fatal(err)
		}
	case "bootstrap":
		if err := runBootstrap(ctx, args); err != nil {
			fatal(err)
		}
	case "recover-admin":
		if err := runRecoverAdmin(ctx, args); err != nil {
			fatal(err)
		}
	case "-h", "--help", "help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", sub)
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w *os.File) {
	fmt.Fprintln(w, "Usage: protosource-authmgr <subcommand> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Subcommands:")
	fmt.Fprintln(w, "  ensure-tables    Create the DynamoDB tables if they do not exist.")
	fmt.Fprintln(w, "  bootstrap        Create default issuer + super-admin role + admin user.")
	fmt.Fprintln(w, "  recover-admin    Create a fresh admin alongside existing ones (lost-admin recovery).")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "All subcommands read the PROTOSOURCE_AUTH_* environment variables shared with")
	fmt.Fprintln(w, "cmd/protosource-auth. Bootstrap and recover-admin additionally require")
	fmt.Fprintln(w, "PROTOSOURCE_AUTH_SEED_SECRET to be set.")
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

// ── Subcommand: ensure-tables ──

func runEnsureTables(ctx context.Context, args []string) error {
	cfg, err := loadConfigForMgr()
	if err != nil {
		return err
	}
	if cfg.Backend != app.BackendDynamoDB {
		return fmt.Errorf("ensure-tables only applies to the dynamodb backend (set %s=dynamodb)", app.EnvBackend)
	}

	client, err := app.NewDynamoDBClient(ctx, cfg)
	if err != nil {
		return fmt.Errorf("dynamodb client: %w", err)
	}
	if err := dynamodbstore.EnsureTables(ctx, client, cfg.EventsTable, cfg.AggregatesTable); err != nil {
		return err
	}
	log.Printf("ensured tables events=%q aggregates=%q", cfg.EventsTable, cfg.AggregatesTable)
	return nil
}

// ── Subcommand: bootstrap ──

func runBootstrap(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	cfg, err := loadConfigForMgr()
	if err != nil {
		return err
	}

	// Allow --admin-email and --admin-password to override env vars.
	if v := flags.get("admin-email"); v != "" {
		cfg.BootstrapAdminEmail = v
	}
	if v := flags.get("admin-password"); v != "" {
		cfg.BootstrapAdminPassword = v
	}

	if cfg.BootstrapAdminEmail == "" || cfg.BootstrapAdminPassword == "" {
		return fmt.Errorf("bootstrap requires --admin-email and --admin-password (or %s / %s env vars)",
			app.EnvBootstrapAdminEmail, app.EnvBootstrapAdminPassword)
	}
	if err := requireSeedSecret(); err != nil {
		return err
	}

	bundle, err := app.NewBundle(ctx, cfg)
	if err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}
	defer func() { _ = bundle.Close() }()

	// Ensure tables exist when running against DynamoDB so a fresh
	// deployment's "bootstrap" step is one call instead of two.
	if cfg.Backend == app.BackendDynamoDB {
		client, err := app.NewDynamoDBClient(ctx, cfg)
		if err != nil {
			return fmt.Errorf("dynamodb client: %w", err)
		}
		if err := dynamodbstore.EnsureTables(ctx, client, cfg.EventsTable, cfg.AggregatesTable); err != nil {
			return fmt.Errorf("ensure tables: %w", err)
		}
	}

	result, err := app.Bootstrap(ctx, cfg, bundle, nil)
	if err != nil {
		return err
	}
	log.Printf(
		"bootstrap complete: issuer=%q role=%q user=%q email=%q",
		result.IssuerID, result.RoleID, result.UserID, result.Email,
	)
	return nil
}

// ── Subcommand: recover-admin ──

func runRecoverAdmin(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	cfg, err := loadConfigForMgr()
	if err != nil {
		return err
	}

	if v := flags.get("admin-email"); v != "" {
		cfg.BootstrapAdminEmail = v
	}
	if v := flags.get("admin-password"); v != "" {
		cfg.BootstrapAdminPassword = v
	}

	if cfg.BootstrapAdminEmail == "" || cfg.BootstrapAdminPassword == "" {
		return fmt.Errorf("recover-admin requires --admin-email and --admin-password")
	}
	if !flags.has("force") {
		return errors.New("recover-admin is destructive — pass --force to confirm")
	}
	if err := requireSeedSecret(); err != nil {
		return err
	}

	bundle, err := app.NewBundle(ctx, cfg)
	if err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}
	defer func() { _ = bundle.Close() }()

	// Generate timestamped ids so the recovered admin is distinct
	// from any existing bootstrap admin. Both the role and user get
	// fresh ids; the existing super-admin role (if any) is left
	// alone so its grants persist unchanged.
	ts := time.Now().UTC().Format("20060102-150405")
	opts := &app.BootstrapOptions{
		RoleID: fmt.Sprintf("role-super-admin-recovery-%s", ts),
		UserID: fmt.Sprintf("user-recovery-admin-%s", ts),
	}

	log.Printf("recover-admin: creating fresh super-admin role=%q user=%q email=%q — THIS IS A DESTRUCTIVE OPERATION; audit this action",
		opts.RoleID, opts.UserID, cfg.BootstrapAdminEmail)

	result, err := app.Bootstrap(ctx, cfg, bundle, opts)
	if err != nil {
		return err
	}
	log.Printf(
		"recover-admin complete: issuer=%q role=%q user=%q email=%q",
		result.IssuerID, result.RoleID, result.UserID, result.Email,
	)
	return nil
}

// ── Helpers ──

func loadConfigForMgr() (*app.Config, error) {
	cfg, err := app.LoadConfigFromEnv()
	if err != nil {
		return nil, err
	}
	// mgr is primarily operational for persistent backends — warn
	// but do not fail when pointed at memorystore since phase 8
	// supports both for the running binary.
	if cfg.Backend == app.BackendMemory {
		log.Printf("warning: mgr against %s=memory has no persistence — nothing survives process exit", app.EnvBackend)
	}
	return cfg, nil
}

func requireSeedSecret() error {
	if strings.TrimSpace(os.Getenv(EnvSeedSecret)) == "" {
		return fmt.Errorf("%s must be set (phase 9 gate against accidental invocation)", EnvSeedSecret)
	}
	return nil
}

// cliFlags is a minimal --key=value / --key value / --flag parser
// matching the style of protosource's generated *mgr CLIs.
type cliFlags struct {
	positionals []string
	named       map[string]string
	bools       map[string]bool
}

func parseFlags(args []string) cliFlags {
	f := cliFlags{named: make(map[string]string), bools: make(map[string]bool)}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if !strings.HasPrefix(a, "--") {
			f.positionals = append(f.positionals, a)
			continue
		}
		key := strings.TrimPrefix(a, "--")
		if eq := strings.IndexByte(key, '='); eq >= 0 {
			f.named[key[:eq]] = key[eq+1:]
			continue
		}
		// --flag or --flag value
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			f.named[key] = args[i+1]
			i++
			continue
		}
		f.bools[key] = true
	}
	return f
}

func (f cliFlags) get(key string) string { return f.named[key] }

func (f cliFlags) has(key string) bool {
	if _, ok := f.named[key]; ok {
		return true
	}
	return f.bools[key]
}
