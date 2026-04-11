// Package app wires the protosource-auth service from a [Config] into a
// ready-to-serve [http.Handler]. It is kept out of cmd/protosource-auth
// so the full binary can be exercised in-process from tests via
// [Run].
//
// Phase 7 uses memorystore for every aggregate — state is lost on
// process exit. Startup bootstrap (via BOOTSTRAP_EMAIL /
// BOOTSTRAP_PASSWORD env vars) runs every time the binary starts and is
// idempotent by construction against a fresh in-memory state. A later
// phase will swap in a persistent store and make bootstrap run only
// once (or only on --force-recover).
package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the runtime configuration for a protosource-auth instance.
// Zero-value fields are populated with defaults by [Config.Normalize].
type Config struct {
	// ListenAddr is the TCP address the HTTP listener binds to
	// (e.g. ":8080"). Default: ":8080".
	ListenAddr string

	// MasterKey is the raw 32-byte master key used by the local
	// KeyProvider to envelope-encrypt signing-key private material.
	// Construct via [LoadConfigFromEnv] from a base64-encoded env
	// variable, or assign directly in tests.
	MasterKey []byte

	// IssuerID is the aggregate id of the default (and, in phase 7,
	// only) Issuer registered at bootstrap. Default: "default".
	IssuerID string

	// IssuerIss is the JWT "iss" claim value advertised by the default
	// issuer. Required — empty panics at [Run].
	IssuerIss string

	// IssuerDisplayName is the human-readable name for the issuer.
	// Default: "protosource-auth".
	IssuerDisplayName string

	// TokenTTL is how long issued shadow tokens live. Default 10h.
	TokenTTL time.Duration

	// BootstrapAdminEmail, if non-empty, enables startup bootstrap:
	// the service creates a default Issuer, a super-admin Role
	// granting "*", an ACTIVE User with the provided email and
	// password, and assigns the super-admin role to it. In phase 7
	// this runs on every startup because the memorystore resets;
	// when we switch to persistent storage it will become a
	// first-run-only operation.
	BootstrapAdminEmail string

	// BootstrapAdminPassword is the plaintext password for the
	// bootstrap admin user. Required when BootstrapAdminEmail is
	// set. Hashed with argon2id before it is stored.
	BootstrapAdminPassword string

	// BootstrapActor is the "actor" recorded on bootstrap commands.
	// Default: "bootstrap".
	BootstrapActor string
}

// Env variable names consulted by [LoadConfigFromEnv].
const (
	EnvListenAddr             = "PROTOSOURCE_AUTH_LISTEN_ADDR"
	EnvMasterKey              = "PROTOSOURCE_AUTH_LOCAL_MASTER_KEY"
	EnvIssuerID               = "PROTOSOURCE_AUTH_ISSUER_ID"
	EnvIssuerIss              = "PROTOSOURCE_AUTH_ISSUER_ISS"
	EnvIssuerDisplayName      = "PROTOSOURCE_AUTH_ISSUER_DISPLAY_NAME"
	EnvTokenTTL               = "PROTOSOURCE_AUTH_TOKEN_TTL"
	EnvBootstrapAdminEmail    = "PROTOSOURCE_AUTH_BOOTSTRAP_EMAIL"
	EnvBootstrapAdminPassword = "PROTOSOURCE_AUTH_BOOTSTRAP_PASSWORD"
)

// LoadConfigFromEnv returns a Config populated from the environment.
// Returns an error if required variables are missing or malformed.
func LoadConfigFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:             os.Getenv(EnvListenAddr),
		IssuerID:               os.Getenv(EnvIssuerID),
		IssuerIss:              os.Getenv(EnvIssuerIss),
		IssuerDisplayName:      os.Getenv(EnvIssuerDisplayName),
		BootstrapAdminEmail:    os.Getenv(EnvBootstrapAdminEmail),
		BootstrapAdminPassword: os.Getenv(EnvBootstrapAdminPassword),
	}

	if raw := os.Getenv(EnvMasterKey); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("app: invalid %s: %w", EnvMasterKey, err)
		}
		cfg.MasterKey = key
	}

	if raw := os.Getenv(EnvTokenTTL); raw != "" {
		// Accept either a duration ("10h") or an integer number of
		// seconds ("36000").
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.TokenTTL = d
		} else if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			cfg.TokenTTL = time.Duration(n) * time.Second
		} else {
			return nil, fmt.Errorf("app: invalid %s: %q", EnvTokenTTL, raw)
		}
	}

	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Normalize applies default values to unset fields and validates
// required fields. Called automatically by [LoadConfigFromEnv] and
// [Run].
func (c *Config) Normalize() error {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8080"
	}
	if c.IssuerID == "" {
		c.IssuerID = "default"
	}
	if c.IssuerDisplayName == "" {
		c.IssuerDisplayName = "protosource-auth"
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = 10 * time.Hour
	}
	if c.BootstrapActor == "" {
		c.BootstrapActor = "bootstrap"
	}

	if len(c.MasterKey) == 0 {
		return errors.New("app: MasterKey is required (set " + EnvMasterKey + ")")
	}
	if c.IssuerIss == "" {
		return errors.New("app: IssuerIss is required (set " + EnvIssuerIss + ")")
	}
	if c.BootstrapAdminEmail != "" && c.BootstrapAdminPassword == "" {
		return errors.New("app: BootstrapAdminPassword is required when BootstrapAdminEmail is set")
	}
	return nil
}
