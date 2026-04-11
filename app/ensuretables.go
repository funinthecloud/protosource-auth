package app

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// NumGSIs is the number of GSI pairs on the aggregates table. The
// value is fixed by the protosource opaquedata single-table design —
// every aggregate with opaque_field annotations projects into one of
// these 20 slots.
const NumGSIs = 20

// EnsureTables idempotently creates the events and aggregates tables
// against the given client. If a table already exists it is left
// alone (including its indexes and TTL settings). Intended for
// tests, local development against DynamoDB Local, and first-run
// bootstrap scripts.
//
// Real production deployments should provision tables via the
// CloudFormation template shipped by protosource — the helper does
// not reconcile GSI changes, billing mode, or PITR.
//
// Schema:
//
//	events table
//	  a (S) — partition key (aggregate id)
//	  v (N) — sort key (version)
//	  t (N) — optional TTL attribute, enabled via UpdateTimeToLive
//	  billing: PAY_PER_REQUEST
//
//	aggregates table
//	  pk (S) — partition key
//	  sk (S) — sort key
//	  gsi{n}pk (S) / gsi{n}sk (S) for n in 1..20, each as a GSI
//	    projecting ALL attributes
//	  t (N) — optional TTL attribute
//	  billing: PAY_PER_REQUEST
func EnsureTables(ctx context.Context, client *dynamodb.Client, eventsTable, aggregatesTable string) error {
	if err := ensureEventsTable(ctx, client, eventsTable); err != nil {
		return fmt.Errorf("ensure events table %q: %w", eventsTable, err)
	}
	if err := ensureAggregatesTable(ctx, client, aggregatesTable); err != nil {
		return fmt.Errorf("ensure aggregates table %q: %w", aggregatesTable, err)
	}
	return nil
}

func ensureEventsTable(ctx context.Context, client *dynamodb.Client, name string) error {
	exists, err := tableExists(ctx, client, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: aws.String(name),
		AttributeDefinitions: []types.AttributeDefinition{
			{AttributeName: aws.String("a"), AttributeType: types.ScalarAttributeTypeS},
			{AttributeName: aws.String("v"), AttributeType: types.ScalarAttributeTypeN},
		},
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("a"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("v"), KeyType: types.KeyTypeRange},
		},
		BillingMode: types.BillingModePayPerRequest,
	})
	if err != nil {
		return fmt.Errorf("CreateTable: %w", err)
	}
	if err := waitActive(ctx, client, name); err != nil {
		return err
	}
	// TTL is best-effort — DynamoDB Local doesn't always support it
	// but the real service does. We log and continue on failure so
	// local test runs don't break just because the TTL call errored.
	_, _ = client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(name),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String("t"),
			Enabled:       aws.Bool(true),
		},
	})
	return nil
}

func ensureAggregatesTable(ctx context.Context, client *dynamodb.Client, name string) error {
	exists, err := tableExists(ctx, client, name)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	attrs := []types.AttributeDefinition{
		{AttributeName: aws.String("pk"), AttributeType: types.ScalarAttributeTypeS},
		{AttributeName: aws.String("sk"), AttributeType: types.ScalarAttributeTypeS},
	}
	var gsis []types.GlobalSecondaryIndex
	for i := 1; i <= NumGSIs; i++ {
		n := strconv.Itoa(i)
		pkAttr := "gsi" + n + "pk"
		skAttr := "gsi" + n + "sk"
		attrs = append(attrs,
			types.AttributeDefinition{AttributeName: aws.String(pkAttr), AttributeType: types.ScalarAttributeTypeS},
			types.AttributeDefinition{AttributeName: aws.String(skAttr), AttributeType: types.ScalarAttributeTypeS},
		)
		gsis = append(gsis, types.GlobalSecondaryIndex{
			// Index name is "gsi{N}pk-gsi{N}sk-index" — the
			// opaquedata dynamo layer computes exactly this name
			// when issuing Query calls, so EnsureTables must match.
			IndexName: aws.String(pkAttr + "-" + skAttr + "-index"),
			KeySchema: []types.KeySchemaElement{
				{AttributeName: aws.String(pkAttr), KeyType: types.KeyTypeHash},
				{AttributeName: aws.String(skAttr), KeyType: types.KeyTypeRange},
			},
			Projection: &types.Projection{ProjectionType: types.ProjectionTypeAll},
		})
	}

	_, err = client.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName:            aws.String(name),
		AttributeDefinitions: attrs,
		KeySchema: []types.KeySchemaElement{
			{AttributeName: aws.String("pk"), KeyType: types.KeyTypeHash},
			{AttributeName: aws.String("sk"), KeyType: types.KeyTypeRange},
		},
		GlobalSecondaryIndexes: gsis,
		BillingMode:            types.BillingModePayPerRequest,
	})
	if err != nil {
		return fmt.Errorf("CreateTable: %w", err)
	}
	if err := waitActive(ctx, client, name); err != nil {
		return err
	}
	_, _ = client.UpdateTimeToLive(ctx, &dynamodb.UpdateTimeToLiveInput{
		TableName: aws.String(name),
		TimeToLiveSpecification: &types.TimeToLiveSpecification{
			AttributeName: aws.String("t"),
			Enabled:       aws.Bool(true),
		},
	})
	return nil
}

func tableExists(ctx context.Context, client *dynamodb.Client, name string) (bool, error) {
	_, err := client.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(name)})
	if err == nil {
		return true, nil
	}
	var nf *types.ResourceNotFoundException
	if errors.As(err, &nf) {
		return false, nil
	}
	return false, err
}

// waitActive polls DescribeTable until the table reports ACTIVE or
// the context expires. DynamoDB Local flips to ACTIVE almost
// immediately, but real DynamoDB can take tens of seconds for
// tables with many GSIs.
func waitActive(ctx context.Context, client *dynamodb.Client, name string) error {
	waiter := dynamodb.NewTableExistsWaiter(client)
	return waiter.Wait(ctx, &dynamodb.DescribeTableInput{TableName: aws.String(name)}, 2*time.Minute)
}
