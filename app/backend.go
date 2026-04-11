package app

import (
	"context"
	"fmt"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/service"
)

// storeBundle is the set of aggregate repositories + a UserDirectory
// assembled for a particular backend. [Run] wires this bundle into the
// Loginer + Checker + Service without caring which backend built it.
type storeBundle struct {
	userRepo   service.AggregateRepo
	roleRepo   service.AggregateRepo
	issuerRepo service.AggregateRepo
	keyRepo    service.AggregateRepo
	tokenRepo  service.AggregateRepo

	directory service.UserDirectory

	// close is invoked by [App.Close] to release backend-specific
	// resources (none for the memory backend).
	close func() error
}

// newBundle dispatches on cfg.Backend to build the appropriate bundle.
func newBundle(ctx context.Context, cfg *Config) (*storeBundle, error) {
	switch cfg.Backend {
	case BackendMemory:
		return newMemoryBundle()
	case BackendDynamoDB:
		return newDynamoDBBundle(ctx, cfg)
	default:
		return nil, fmt.Errorf("app: unknown backend %q", cfg.Backend)
	}
}

// newMemoryBundle wires five in-process memorystore-backed repositories
// and a [service.MapDirectory]. State is lost on process exit.
func newMemoryBundle() (*storeBundle, error) {
	serializer := protobinaryserializer.NewSerializer()
	return &storeBundle{
		userRepo:   userv1.NewRepository(memorystore.New(userv1.SnapshotEveryNEvents), serializer),
		roleRepo:   rolev1.NewRepository(memorystore.New(rolev1.SnapshotEveryNEvents), serializer),
		issuerRepo: issuerv1.NewRepository(memorystore.New(0), serializer),
		keyRepo:    keyv1.NewRepository(memorystore.New(0), serializer),
		tokenRepo:  tokenv1.NewRepository(memorystore.New(0), serializer),
		directory:  service.NewMapDirectory(),
	}, nil
}

// emailRegistrar is the optional interface a UserDirectory can satisfy
// to be populated by the startup bootstrap. [service.MapDirectory]
// implements it; directories backed by a durable index (DynamoDB GSI)
// do not — new users are visible as soon as the index propagates.
type emailRegistrar interface {
	Add(email, userID string)
}

// compile-time hint so the linter does not flag the interface as
// unused when the dynamo backend is built out.
var _ = (emailRegistrar)(nil)

// ensureProtosourceStoreNotNil is a tiny runtime guard so
// constructors that accept interface-typed stores loudly reject nil
// misconfigurations at startup rather than on first Apply.
func ensureProtosourceStoreNotNil(name string, s protosource.Store) error {
	if s == nil {
		return fmt.Errorf("app: store %q is nil", name)
	}
	return nil
}
