package app

import (
	"context"
	"fmt"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/service"
)

// Bundle is the set of aggregate repositories + a UserDirectory assembled
// for a particular backend. [Run] wires this bundle into the Loginer +
// Checker + Service without caring which backend built it, and the
// protosource-authmgr CLI calls aggregate commands directly on the
// exposed repositories (bypassing HTTP entirely) for bootstrap and
// recovery flows.
//
// The typed v1.Repo fields satisfy service.AggregateRepo (each
// v1.Repo embeds protosource.Repo) so the Loginer/Checker still accept
// them, while also being narrow enough for the generated v1.Handlers
// to consume directly when [Run] builds the full router.
//
// UserClient … TokenClient are populated for backends that expose an
// opaquedata store (DynamoDB, Cosmos DB) and left nil for the memory
// backend. The presence of UserClient is the signal app.Run uses to
// register the v1 admin handlers — without an opaquedata store there
// is nothing for Get/Load/Query handlers to read from.
type Bundle struct {
	UserRepo   userv1.Repo
	RoleRepo   rolev1.Repo
	IssuerRepo issuerv1.Repo
	KeyRepo    keyv1.Repo
	TokenRepo  tokenv1.Repo

	UserClient   *userv1.UserClient
	RoleClient   *rolev1.RoleClient
	IssuerClient *issuerv1.IssuerClient
	KeyClient    *keyv1.KeyClient
	TokenClient  *tokenv1.TokenClient

	Directory service.UserDirectory

	// CloseFn is invoked by [App.Close] to release backend-specific
	// resources. Nil for the memory backend.
	CloseFn func() error
}

// Close releases resources associated with this Bundle. Safe to call
// on a Bundle with a nil CloseFn.
func (b *Bundle) Close() error {
	if b == nil || b.CloseFn == nil {
		return nil
	}
	return b.CloseFn()
}

// NewBundle constructs a Bundle for the given config. Dispatches on
// cfg.Backend. Errors from the underlying backend factories are
// propagated unchanged.
func NewBundle(ctx context.Context, cfg *Config) (*Bundle, error) {
	if cfg == nil {
		return nil, fmt.Errorf("app: cfg must not be nil")
	}
	if err := cfg.Normalize(); err != nil {
		return nil, err
	}
	switch cfg.Backend {
	case BackendMemory:
		return newMemoryBundle()
	case BackendDynamoDB:
		return newDynamoDBBundle(ctx, cfg)
	case BackendCosmosDB:
		return newCosmosDBBundle(ctx, cfg)
	default:
		return nil, fmt.Errorf("app: unknown backend %q", cfg.Backend)
	}
}

// newMemoryBundle wires five in-process memorystore-backed repositories
// and a [service.MapDirectory]. State is lost on process exit.
//
// The v1 client fields are left nil — memorystore is an event store,
// not an opaquedata.OpaqueStore, so there is no projection layer for
// the generated read/query handlers to query. app.Run falls back to
// the minimal router (login + page) on memory.
func newMemoryBundle() (*Bundle, error) {
	serializer := protobinaryserializer.NewSerializer()
	return &Bundle{
		UserRepo:   userv1.NewRepository(memorystore.New(userv1.SnapshotEveryNEvents), serializer),
		RoleRepo:   rolev1.NewRepository(memorystore.New(rolev1.SnapshotEveryNEvents), serializer),
		IssuerRepo: issuerv1.NewRepository(memorystore.New(0), serializer),
		KeyRepo:    keyv1.NewRepository(memorystore.New(0), serializer),
		TokenRepo:  tokenv1.NewRepository(memorystore.New(0), serializer),
		Directory:  service.NewMapDirectory(),
	}, nil
}

// emailRegistrar is the optional interface a UserDirectory can satisfy
// to be populated by the startup bootstrap. [service.MapDirectory]
// implements it; directories backed by a durable index (DynamoDB GSI)
// do not — new users are visible as soon as the index propagates.
type emailRegistrar interface {
	Add(email, userID string)
}
