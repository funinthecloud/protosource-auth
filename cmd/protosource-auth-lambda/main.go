// Command protosource-auth-lambda runs the shadow-token authentication
// and authorization service as an AWS Lambda function behind API Gateway.
//
// Configuration is read from environment variables:
//
//	PROTOSOURCE_AUTH_EVENTS_TABLE       DynamoDB events table name (default "events")
//	PROTOSOURCE_AUTH_AGGREGATES_TABLE   DynamoDB aggregates table name (default "aggregates")
//	PROTOSOURCE_AUTH_LOCAL_MASTER_KEY   base64(32 random bytes)
//
// The issuer and admin bootstrap are handled by protosource-authmgr
// before the Lambda is deployed — they are not part of the cold-start
// path.
package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/funinthecloud/protosource/adapters/awslambda"
	"github.com/funinthecloud/protosource/stores/dynamodbstore"

	"github.com/funinthecloud/protosource-auth/keyproviders/local"
)

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalf("aws config: %v", err)
	}

	client := dynamodb.NewFromConfig(cfg)

	eventsTable := dynamodbstore.EventsTableName(envOrDefault("PROTOSOURCE_AUTH_EVENTS_TABLE", "events"))
	aggregatesTable := dynamodbstore.AggregatesTableName(envOrDefault("PROTOSOURCE_AUTH_AGGREGATES_TABLE", "aggregates"))

	keyProvider, err := local.FromEnv()
	if err != nil {
		log.Fatalf("key provider: %v", err)
	}

	router, err := InitializeRouter(client, eventsTable, aggregatesTable, keyProvider)
	if err != nil {
		log.Fatalf("initialize: %v", err)
	}

	handler := awslambda.WrapRouter(router, extractActor)
	lambda.Start(handler)
}

// extractActor returns an empty string — the auth service does not
// consume actors from callers; it provides authentication to others.
func extractActor(_ events.APIGatewayProxyRequest) string { return "" }

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
