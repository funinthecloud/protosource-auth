// Command protosource-auth-lambda runs the shadow-token authentication
// and authorization service as an AWS Lambda function behind API Gateway.
//
// Configuration is read from the same environment variables as the
// standard cmd/protosource-auth binary (see app.Config). The Lambda
// template at /template.yaml sets:
//
//	PROTOSOURCE_AUTH_STORE_BACKEND   = dynamodb
//	PROTOSOURCE_AUTH_KEY_PROVIDER    = awskms
//	PROTOSOURCE_AUTH_MASTER_KEY_REF  = KMS key ARN
//	PROTOSOURCE_AUTH_EVENTS_TABLE    = DynamoDB events table
//	PROTOSOURCE_AUTH_AGGREGATES_TABLE = DynamoDB aggregates table
//	PROTOSOURCE_AUTH_ISSUER_ISS      = issuer URL (https://<custom domain>)
//	PROTOSOURCE_AUTH_CORS_ORIGIN     = SPA origin (or empty)
//
// The default issuer + admin bootstrap are handled by protosource-authmgr
// before the Lambda is deployed — they are not part of the cold-start
// path. This binary therefore skips Run's bootstrap branch and wires
// the router directly from the same app.NewBundle / app.NewRouter
// helpers the Container Apps binary uses, so the route set and CORS
// posture stay identical across deployments.
package main

import (
	"context"
	"log"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"

	"github.com/funinthecloud/protosource/adapters/awslambda"
	"github.com/funinthecloud/protosource-auth/app"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

func main() {
	ctx := context.Background()

	cfg, err := app.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	bundle, err := app.NewBundle(ctx, cfg)
	if err != nil {
		log.Fatalf("bundle: %v", err)
	}

	provider, masterKeyRef, err := app.BuildKeyProvider(ctx, cfg)
	if err != nil {
		log.Fatalf("key provider: %v", err)
	}

	resolver := keys.NewResolver(
		bundle.KeyRepo,
		provider,
		masterKeyRef,
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
	)

	router := app.NewRouter(cfg, bundle, resolver)
	handler := awslambda.WrapRouter(router, extractActor)
	lambda.Start(handler)
}

// extractActor returns an empty string — the auth service does not
// consume actors from callers; it provides authentication to others.
func extractActor(_ events.APIGatewayProxyRequest) string { return "" }
