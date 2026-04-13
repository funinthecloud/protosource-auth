package app_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"
	"github.com/funinthecloud/protosource/stores/dynamodbstore"

	"github.com/funinthecloud/protosource-auth/app"
	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
)

// EnvDynamoEndpoint is the env var that, when set, enables the
// DynamoDB integration test in this file. Typical value:
//
//	http://localhost:8000
//
// which is where DynamoDB Local listens by default:
//
//	docker run -p 8000:8000 amazon/dynamodb-local
const EnvDynamoEndpoint = "PROTOSOURCE_AUTH_TEST_DYNAMO_ENDPOINT"

// TestDynamoDBBackendEndToEnd exercises the full auth service against
// a real DynamoDB implementation. Skipped when PROTOSOURCE_AUTH_TEST_
// DYNAMO_ENDPOINT is unset so CI environments without Docker don't
// see a failure.
func TestDynamoDBBackendEndToEnd(t *testing.T) {
	endpoint := os.Getenv(EnvDynamoEndpoint)
	if endpoint == "" {
		t.Skipf("skipping DynamoDB integration test; set %s to run (e.g. http://localhost:8000)", EnvDynamoEndpoint)
	}

	ctx := context.Background()

	// DynamoDB Local partitions its internal storage by (region,
	// access-key) — tables created under one set of credentials are
	// invisible to another. Set static credentials via env vars so
	// both this test's explicit client AND the app's internal
	// LoadDefaultConfig-based client see the same logical database.
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_ACCESS_KEY_ID", "protosourceauthtest")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "protosourceauthtest")
	t.Setenv("AWS_SESSION_TOKEN", "")

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("protosourceauthtest", "protosourceauthtest", "")),
	)
	if err != nil {
		t.Fatalf("LoadDefaultConfig: %v", err)
	}
	client := dynamodb.NewFromConfig(awsCfg, func(o *dynamodb.Options) {
		o.BaseEndpoint = aws.String(endpoint)
	})

	// Use unique per-run table names so repeated runs don't collide
	// with leftover state from previous failures.
	runTag := t.Name() + "-" + randHex(t, 4)
	eventsTable := "events-" + runTag
	aggregatesTable := "aggregates-" + runTag

	if err := dynamodbstore.EnsureTables(ctx, client, eventsTable, aggregatesTable); err != nil {
		t.Fatalf("EnsureTables: %v", err)
	}
	t.Cleanup(func() {
		// Best-effort teardown. Ignore errors — the next run uses
		// a different tag so leftovers are harmless.
		_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(eventsTable)})
		_, _ = client.DeleteTable(ctx, &dynamodb.DeleteTableInput{TableName: aws.String(aggregatesTable)})
	})

	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}

	cfg := &app.Config{
		MasterKey:              masterKey,
		IssuerIss:              "https://auth.dynamo.test",
		Backend:                app.BackendDynamoDB,
		EventsTable:            eventsTable,
		AggregatesTable:        aggregatesTable,
		AWSEndpoint:            endpoint,
		AWSRegion:              "us-east-1",
		BootstrapAdminEmail:    "admin@example.com",
		BootstrapAdminPassword: "hunter2",
	}

	instance, err := app.Run(ctx, cfg)
	if err != nil {
		t.Fatalf("app.Run (dynamodb): %v", err)
	}
	t.Cleanup(func() { _ = instance.Close() })

	if instance.BootstrapResult == nil {
		t.Fatal("bootstrap result is nil")
	}

	// Verify the directory can actually resolve the bootstrap admin
	// via the GSI query before we try to login. Isolates directory
	// failures from credential failures.
	got, err := instance.Directory.FindByEmail(ctx, "admin@example.com")
	if err != nil {
		t.Fatalf("Directory.FindByEmail: %v", err)
	}
	if got != "user-bootstrap-admin" {
		t.Errorf("Directory.FindByEmail = %q, want user-bootstrap-admin", got)
	}

	server := httptest.NewServer(instance.Handler)
	t.Cleanup(server.Close)

	// Login over real HTTP.
	body, _ := json.Marshal(map[string]string{
		"email":    "admin@example.com",
		"password": "hunter2",
		"issuer":   "default",
	})
	resp, err := http.Post(server.URL+"/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /login status %d: %s", resp.StatusCode, dump)
	}
	var login struct {
		ShadowToken string `json:"shadow_token"`
		JWT         string `json:"jwt"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&login); err != nil {
		t.Fatalf("decode login: %v", err)
	}

	// The GSI-backed directory must have resolved alice@example.com.
	if login.ShadowToken == "" {
		t.Fatal("empty shadow token")
	}

	// Use httpauthz to authorize a few function strings — the super-
	// admin role grants "*" so everything should succeed.
	authr := httpauthz.New(server.URL)
	for _, fn := range []string{
		"auth.user.v1.Create",
		"auth.role.v1.AddFunction",
		"showcase.app.todolist.v1.Archive",
	} {
		ctx, err := authr.Authorize(
			context.Background(),
			protosource.Request{Headers: map[string]string{"Authorization": "Bearer " + login.ShadowToken}},
			fn,
		)
		if err != nil {
			t.Errorf("Authorize(%q): %v", fn, err)
			continue
		}
		if authz.UserIDFromContext(ctx) != "user-bootstrap-admin" {
			t.Errorf("UserIDFromContext for %q = %q", fn, authz.UserIDFromContext(ctx))
		}
	}

	// Bogus token must be rejected.
	_, err = authr.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Authorization": "Bearer nope"}},
		"auth.user.v1.Create",
	)
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Authorize(bad token) = %v, want ErrUnauthenticated", err)
	}
}

func randHex(t *testing.T, n int) string {
	t.Helper()
	const hex = "0123456789abcdef"
	buf := make([]byte, n*2)
	for i := range buf {
		buf[i] = hex[int(time.Now().UnixNano()>>uint(i%32))&0xf]
	}
	return string(buf)
}
