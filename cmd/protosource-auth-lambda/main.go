// Command protosource-auth-lambda runs the shadow-token authentication
// and authorization service as an AWS Lambda function behind API Gateway.
//
// Configuration is read from environment variables:
//
//	EVENTS_TABLE                        DynamoDB events table name
//	AGGREGATES_TABLE                    DynamoDB aggregates table name
//	PROTOSOURCE_AUTH_LOCAL_MASTER_KEY   base64(32 random bytes)
//	PROTOSOURCE_AUTH_ISSUER_ISS         JWT "iss" claim
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

	eventsTable := dynamodbstore.EventsTableName(envOrDefault("EVENTS_TABLE", "protosource-auth-events"))
	aggregatesTable := dynamodbstore.AggregatesTableName(envOrDefault("AGGREGATES_TABLE", "protosource-auth-aggregates"))
	masterKey := mustDecodeMasterKey()
	issuerIss := IssuerIss(os.Getenv("PROTOSOURCE_AUTH_ISSUER_ISS"))

	router, err := InitializeRouter(client, eventsTable, aggregatesTable, masterKey, issuerIss)
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
	return MasterKey(key)
}
