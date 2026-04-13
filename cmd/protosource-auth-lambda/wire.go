//go:build wireinject

package main

import (
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/goforj/wire"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/aws/dynamoclient"
	"github.com/funinthecloud/protosource/opaquedata"
	opaquedynamo "github.com/funinthecloud/protosource/opaquedata/dynamo"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/dynamodbstore"

	issuerv1dynamodb "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1/issuerv1dynamodb"
	keyv1dynamodb "github.com/funinthecloud/protosource-auth/gen/auth/key/v1/keyv1dynamodb"
	"github.com/funinthecloud/protosource-auth/keyproviders"
	rolev1dynamodb "github.com/funinthecloud/protosource-auth/gen/auth/role/v1/rolev1dynamodb"
	tokenv1dynamodb "github.com/funinthecloud/protosource-auth/gen/auth/token/v1/tokenv1dynamodb"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	userv1dynamodb "github.com/funinthecloud/protosource-auth/gen/auth/user/v1/userv1dynamodb"
)

// InitializeRouter wires all dependencies and returns a configured
// router ready for awslambda.WrapRouter.
func InitializeRouter(
	client *dynamodb.Client,
	eventsTable dynamodbstore.EventsTableName,
	aggregatesTable dynamodbstore.AggregatesTableName,
	keyProvider keyproviders.KeyProvider,
) (*protosource.Router, error) {
	wire.Build(
		// Infrastructure bindings.
		wire.Bind(new(dynamoclient.Client), new(*dynamodb.Client)),
		wire.Bind(new(opaquedata.OpaqueStore), new(*opaquedynamo.Store)),
		dynamodbstore.ProviderSet,
		protobinaryserializer.ProviderSet,

		// Per-aggregate DynamoDB repositories (generated).
		userv1dynamodb.ProviderSet,
		rolev1dynamodb.ProviderSet,
		issuerv1dynamodb.ProviderSet,
		keyv1dynamodb.ProviderSet,
		tokenv1dynamodb.ProviderSet,

		// Generated client for GSI queries.
		userv1.NewUserClient,

		// Auth-service provider functions.
		provideResolver,
		provideDirectory,
		provideLoginer,
		provideChecker,
		provideService,
		provideRouter,
	)
	return nil, nil
}
