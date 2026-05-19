package app

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/dynamodbstore"

	opaquedynamo "github.com/funinthecloud/protosource/opaquedata/dynamo"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
)

// NewDynamoDBClient constructs an AWS SDK DynamoDB client honoring the
// optional AWSEndpoint (for DynamoDB Local / LocalStack) and AWSRegion
// overrides on cfg. Credentials are resolved from the default chain
// (env, shared config, IAM role). Exposed so the mgr CLI can share
// the exact same client configuration the service uses.
func NewDynamoDBClient(ctx context.Context, cfg *Config) (*dynamodb.Client, error) {
	var loadOpts []func(*awsconfig.LoadOptions) error
	if cfg.AWSRegion != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.AWSRegion))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, err
	}

	var clientOpts []func(*dynamodb.Options)
	if cfg.AWSEndpoint != "" {
		endpoint := cfg.AWSEndpoint
		clientOpts = append(clientOpts, func(o *dynamodb.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}
	return dynamodb.NewFromConfig(awsCfg, clientOpts...), nil
}

// newDynamoDBBundle wires all five aggregate repositories against a
// single shared [dynamodbstore.DynamoDBStore] and returns a bundle
// whose UserDirectory is GSI-backed (queries User.email via the
// generated UserClient's SelectUserByEmail).
//
// Table creation is out of scope here — the tables named in cfg must
// already exist. See [EnsureTables] for a test/local-dev helper that
// creates them idempotently, or provision them via the CloudFormation
// template shipped by protosource.
func newDynamoDBBundle(ctx context.Context, cfg *Config) (*Bundle, error) {
	client, err := NewDynamoDBClient(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("app: dynamodb client: %w", err)
	}

	opaqueStore := opaquedynamo.New(client, cfg.AggregatesTable)
	dynStore, err := dynamodbstore.New(
		client,
		dynamodbstore.WithEventsTable(cfg.EventsTable),
		dynamodbstore.WithOpaqueStore(opaqueStore),
	)
	if err != nil {
		return nil, fmt.Errorf("app: dynamodb store: %w", err)
	}

	serializer := protobinaryserializer.NewSerializer()

	userClient := userv1.NewUserClient(opaqueStore)

	return &Bundle{
		UserRepo:   userv1.NewRepository(dynStore, serializer),
		RoleRepo:   rolev1.NewRepository(dynStore, serializer),
		IssuerRepo: issuerv1.NewRepository(dynStore, serializer),
		KeyRepo:    keyv1.NewRepository(dynStore, serializer),
		TokenRepo:  tokenv1.NewRepository(dynStore, serializer),
		Directory:  NewOpaqueDirectory(userClient),
	}, nil
}
