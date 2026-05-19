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
	"strings"
	"time"
)

// Backend identifies which storage backend [Run] wires behind the
// aggregate repositories.
type Backend string

const (
	// BackendMemory uses an in-process memorystore per aggregate. State
	// is lost on process exit; intended for local development, unit
	// tests, and demos.
	BackendMemory Backend = "memory"
	// BackendDynamoDB uses a shared DynamoDB event store + opaquedata
	// store. Tables must already exist (see [EnsureTables] for a
	// test/local-dev helper, or provision via the CloudFormation
	// template shipped by protosource).
	BackendDynamoDB Backend = "dynamodb"
	// BackendCosmosDB uses a shared Azure Cosmos DB (NoSQL API) event
	// store + opaquedata store. Database + containers must already
	// exist (see protosource-authmgr ensure-tables for an idempotent
	// helper, or provision via the upstream tofu modules).
	BackendCosmosDB Backend = "cosmosdb"
)

// KeyProvider identifies which envelope-encryption provider [Run]
// wires behind the keys.Resolver for wrapping signing-key material.
type KeyProvider string

const (
	// KeyProviderLocal uses an in-process XChaCha20-Poly1305 KEK
	// derived from a 32-byte master key (see [keyproviders/local]).
	// Intended for development and tests; never use for production
	// — there is no HSM root of trust.
	KeyProviderLocal KeyProvider = "local"
	// KeyProviderAWSKMS wraps signing-key material via AWS KMS
	// direct encryption (see [keyproviders/awskms]). Requires
	// MasterKeyRef to be a KMS key ARN or alias.
	KeyProviderAWSKMS KeyProvider = "awskms"
	// KeyProviderAzureKeyVault wraps signing-key material via Azure
	// Key Vault RSA-OAEP-256 against an HSM-backed KEK (see
	// [keyproviders/azurekeyvault]). Requires MasterKeyRef to be a
	// full Key Vault key identifier URL
	// (https://<vault>.vault.azure.net/keys/<name>[/<version>]).
	KeyProviderAzureKeyVault KeyProvider = "azurekeyvault"
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
	// variable, or assign directly in tests. Required only when
	// KeyProvider is [KeyProviderLocal].
	MasterKey []byte

	// KeyProvider selects which envelope-encryption provider wraps
	// signing-key material. Default: [KeyProviderLocal].
	KeyProvider KeyProvider

	// MasterKeyRef is the cloud-side identifier passed to the
	// KeyProvider on Encrypt/Decrypt: a KMS key ARN/alias for
	// [KeyProviderAWSKMS], a Key Vault key identifier URL for
	// [KeyProviderAzureKeyVault]. Ignored (defaulted to
	// "local-master") for [KeyProviderLocal].
	MasterKeyRef string

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

	// Backend selects the storage backend wired behind the aggregate
	// repositories. Default: [BackendMemory].
	Backend Backend

	// EventsTable names the storage unit for the event log:
	//
	//   - DynamoDB:  table name (default "events")
	//   - Cosmos DB: container id (default "events")
	//
	// The field carries a Dynamo-flavored name for backward
	// compatibility; the Cosmos backend treats it as a container id.
	// [EnvEventsContainer] is provided as a clearer-named env-var
	// alias for the Cosmos use case — both env vars map to this
	// single field.
	EventsTable string

	// AggregatesTable names the storage unit for materialized
	// aggregates (opaquedata):
	//
	//   - DynamoDB:  table name (default "aggregates")
	//   - Cosmos DB: container id (default "aggregates")
	//
	// See [EventsTable] regarding the cross-backend naming.
	// [EnvAggregatesContainer] is the Cosmos-flavored env-var alias.
	AggregatesTable string

	// AWSEndpoint overrides the AWS SDK's endpoint resolution. Set to
	// "http://localhost:8000" (or wherever DynamoDB Local is
	// listening) for local development. Leave empty for real AWS.
	AWSEndpoint string

	// AWSRegion overrides the AWS SDK's region. Defaults to whatever
	// the SDK resolves from env/profile.
	AWSRegion string

	// CosmosEndpoint is the Azure Cosmos DB account endpoint URL
	// (https://<account>.documents.azure.com:443/, or the emulator's
	// https://localhost:8081). Required when Backend is
	// [BackendCosmosDB].
	CosmosEndpoint string

	// CosmosKey is the Cosmos primary key for shared-key auth. Used
	// only against the local emulator or for break-glass auth — in
	// production, prefer Managed Identity via
	// CosmosUseDefaultCredential.
	CosmosKey string

	// CosmosUseDefaultCredential, when true, authenticates to Cosmos
	// via [azidentity.NewDefaultAzureCredential] (Managed Identity,
	// az login, environment, etc). Ignored when CosmosKey is set.
	CosmosUseDefaultCredential bool

	// CosmosDatabase is the Cosmos database id. Default:
	// "protosource-auth".
	CosmosDatabase string

	// CosmosInsecureTLS, when true, skips TLS verification on the
	// Cosmos SDK transport — required for the local Cosmos emulator
	// (self-signed cert). Never enable against a real Cosmos
	// account.
	CosmosInsecureTLS bool

	// BootstrapAdminEmail, if non-empty, enables startup bootstrap:
	// the service creates a default Issuer, a super-admin Role
	// granting "*", an ACTIVE User with the provided email and
	// password, and assigns the super-admin role to it. With
	// [BackendMemory] this runs on every startup; with
	// [BackendDynamoDB] it's idempotent in spirit (re-running will
	// fail at the first ErrAlreadyCreated and the existing admin
	// persists).
	BootstrapAdminEmail string

	// BootstrapAdminPassword is the plaintext password for the
	// bootstrap admin user. Required when BootstrapAdminEmail is
	// set. Hashed with argon2id before it is stored.
	BootstrapAdminPassword string

	// BootstrapActor is the "actor" recorded on bootstrap commands.
	// Default: "bootstrap".
	BootstrapActor string

	// CORSOrigin is a comma-separated list of allowed origins for
	// CORS. Empty disables CORS (no Access-Control-Allow-* headers
	// and no preflight handling). Required when the admin SPA is
	// hosted on a different origin than the API. Methods are fixed
	// at GET,POST,OPTIONS and headers at Content-Type,Accept;
	// credentials are always allowed when CORSOrigin is set so the
	// shadow cookie can flow on cross-origin XHR.
	CORSOrigin string
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
	EnvBackend                = "PROTOSOURCE_AUTH_STORE_BACKEND"
	EnvEventsTable            = "PROTOSOURCE_AUTH_EVENTS_TABLE"
	EnvAggregatesTable        = "PROTOSOURCE_AUTH_AGGREGATES_TABLE"
	EnvAWSEndpoint            = "PROTOSOURCE_AUTH_AWS_ENDPOINT"
	EnvAWSRegion              = "PROTOSOURCE_AUTH_AWS_REGION"

	EnvCORSOrigin = "PROTOSOURCE_AUTH_CORS_ORIGIN"

	EnvKeyProvider  = "PROTOSOURCE_AUTH_KEY_PROVIDER"
	EnvMasterKeyRef = "PROTOSOURCE_AUTH_MASTER_KEY_REF"
	EnvPort         = "PORT" // Container Apps / Functions / Cloud Run convention.

	EnvCosmosEndpoint             = "PROTOSOURCE_AUTH_COSMOS_ENDPOINT"
	EnvCosmosKey                  = "PROTOSOURCE_AUTH_COSMOS_KEY"
	EnvCosmosUseDefaultCredential = "PROTOSOURCE_AUTH_COSMOS_USE_DEFAULT_CREDENTIAL"
	EnvCosmosDatabase             = "PROTOSOURCE_AUTH_COSMOS_DATABASE"
	EnvCosmosInsecureTLS          = "PROTOSOURCE_AUTH_COSMOS_INSECURE_TLS"

	// EnvEventsContainer / EnvAggregatesContainer are Cosmos-flavored
	// aliases for EnvEventsTable / EnvAggregatesTable. The container
	// envs win when both are set, so an Azure deployment can be
	// configured without any "table"-named knobs in its environment.
	EnvEventsContainer     = "PROTOSOURCE_AUTH_EVENTS_CONTAINER"
	EnvAggregatesContainer = "PROTOSOURCE_AUTH_AGGREGATES_CONTAINER"
)

// LoadConfigFromEnv returns a Config populated from the environment.
// Returns an error if required variables are missing or malformed.
func LoadConfigFromEnv() (*Config, error) {
	portAddr, err := portToListenAddr(os.Getenv(EnvPort))
	if err != nil {
		return nil, err
	}
	cfg := &Config{
		ListenAddr:             firstNonEmpty(os.Getenv(EnvListenAddr), portAddr),
		IssuerID:               os.Getenv(EnvIssuerID),
		IssuerIss:              os.Getenv(EnvIssuerIss),
		IssuerDisplayName:      os.Getenv(EnvIssuerDisplayName),
		BootstrapAdminEmail:    os.Getenv(EnvBootstrapAdminEmail),
		BootstrapAdminPassword: os.Getenv(EnvBootstrapAdminPassword),
		Backend:                Backend(os.Getenv(EnvBackend)),
		EventsTable:            firstNonEmpty(os.Getenv(EnvEventsContainer), os.Getenv(EnvEventsTable)),
		AggregatesTable:        firstNonEmpty(os.Getenv(EnvAggregatesContainer), os.Getenv(EnvAggregatesTable)),
		AWSEndpoint:            os.Getenv(EnvAWSEndpoint),
		AWSRegion:              os.Getenv(EnvAWSRegion),
		KeyProvider:            KeyProvider(os.Getenv(EnvKeyProvider)),
		MasterKeyRef:           os.Getenv(EnvMasterKeyRef),
		CORSOrigin:             os.Getenv(EnvCORSOrigin),

		CosmosEndpoint:             os.Getenv(EnvCosmosEndpoint),
		CosmosKey:                  os.Getenv(EnvCosmosKey),
		CosmosUseDefaultCredential: envTrue(EnvCosmosUseDefaultCredential),
		CosmosDatabase:             os.Getenv(EnvCosmosDatabase),
		CosmosInsecureTLS:          envTrue(EnvCosmosInsecureTLS),
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
	if c.KeyProvider == "" {
		c.KeyProvider = KeyProviderLocal
	}
	if c.KeyProvider == KeyProviderLocal {
		// The local provider does not consult MasterKeyRef — the
		// docstring says so — so pin it to the documented sentinel
		// even if an operator left a stray cloud kid URL in
		// PROTOSOURCE_AUTH_MASTER_KEY_REF. Silent override matches
		// the field docs and the historical hardcoded constant.
		c.MasterKeyRef = "local-master"
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
	if c.Backend == "" {
		c.Backend = BackendMemory
	}
	if c.EventsTable == "" {
		c.EventsTable = "events"
	}
	if c.AggregatesTable == "" {
		c.AggregatesTable = "aggregates"
	}
	if c.CosmosDatabase == "" {
		c.CosmosDatabase = "protosource-auth"
	}

	if c.IssuerIss == "" {
		return errors.New("app: IssuerIss is required (set " + EnvIssuerIss + ")")
	}
	if c.BootstrapAdminEmail != "" && c.BootstrapAdminPassword == "" {
		return errors.New("app: BootstrapAdminPassword is required when BootstrapAdminEmail is set")
	}
	switch c.Backend {
	case BackendMemory, BackendDynamoDB, BackendCosmosDB:
		// ok
	default:
		return errors.New("app: unknown Backend " + string(c.Backend) + " (want memory, dynamodb, or cosmosdb)")
	}
	switch c.KeyProvider {
	case KeyProviderLocal, KeyProviderAWSKMS, KeyProviderAzureKeyVault:
		// ok
	default:
		return errors.New("app: unknown KeyProvider " + string(c.KeyProvider) + " (want local, awskms, or azurekeyvault)")
	}
	if c.KeyProvider != KeyProviderLocal && c.MasterKeyRef == "" {
		return errors.New("app: MasterKeyRef is required when KeyProvider=" + string(c.KeyProvider) + " (set " + EnvMasterKeyRef + ")")
	}
	if c.Backend == BackendCosmosDB {
		if c.CosmosEndpoint == "" {
			return errors.New("app: CosmosEndpoint is required when Backend=cosmosdb (set " + EnvCosmosEndpoint + ")")
		}
		if c.CosmosKey == "" && !c.CosmosUseDefaultCredential {
			return errors.New("app: Cosmos auth is required when Backend=cosmosdb (set " + EnvCosmosKey + " or " + EnvCosmosUseDefaultCredential + "=1)")
		}
	}
	return nil
}

// portToListenAddr converts a $PORT value to a ":PORT" listen
// address, or returns "" when port is empty. Kept narrow so
// LoadConfigFromEnv can fold the Container Apps / Functions / Cloud
// Run PORT convention into ListenAddr at parse time — Normalize
// stays a pure function of the Config fields it's given.
// Validates that the value is a TCP port (integer in 1-65535) so an
// operator typo surfaces here instead of as a less-actionable bind
// failure deep in startup.
func portToListenAddr(port string) (string, error) {
	if port == "" {
		return "", nil
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("app: invalid %s: %q (want an integer 1-65535)", EnvPort, port)
	}
	return ":" + port, nil
}

// firstNonEmpty returns the first non-empty argument, or "" if every
// argument is empty. Used to give Cosmos-flavored env vars precedence
// over their Dynamo-named aliases.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// envTrue reports whether the given env variable is set to a truthy
// value ("1", "true", "yes", case-insensitive). Used for boolean
// config flags that default to false.
func envTrue(key string) bool {
	switch strings.ToLower(os.Getenv(key)) {
	case "1", "true", "yes":
		return true
	}
	return false
}
