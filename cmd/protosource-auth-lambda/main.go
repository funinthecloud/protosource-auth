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
	"encoding/base64"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/funinthecloud/protosource/adapters/awslambda"
	"github.com/funinthecloud/protosource/stores/dynamodbstore"
)

func main() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		panic(err)
	}

	client := dynamodb.NewFromConfig(cfg)

	eventsTable := dynamodbstore.EventsTableName(envOrDefault("PROTOSOURCE_AUTH_EVENTS_TABLE", "events"))
	aggregatesTable := dynamodbstore.AggregatesTableName(envOrDefault("PROTOSOURCE_AUTH_AGGREGATES_TABLE", "aggregates"))
	masterKey := mustDecodeMasterKey()

	router, err := InitializeRouter(client, eventsTable, aggregatesTable, masterKey)
	if err != nil {
		panic(err)
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

func mustDecodeMasterKey() MasterKey {
	raw := os.Getenv("PROTOSOURCE_AUTH_LOCAL_MASTER_KEY")
	if raw == "" {
		panic("PROTOSOURCE_AUTH_LOCAL_MASTER_KEY is required")
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		panic(fmt.Sprintf("PROTOSOURCE_AUTH_LOCAL_MASTER_KEY: invalid base64: %v", err))
	}
	if len(key) != 32 {
		panic(fmt.Sprintf("PROTOSOURCE_AUTH_LOCAL_MASTER_KEY: decoded key is %d bytes, want 32", len(key)))
	}
	return MasterKey(key)
}
