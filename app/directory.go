package app

import (
	"context"
	"fmt"

	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/service"
)

// OpaqueDirectory satisfies [service.UserDirectory] by running the
// generated UserClient's email GSI query against whichever opaque
// store backs it (DynamoDB, Cosmos DB, ...). Because User.email is
// annotated as GSI1PK on the User aggregate, SelectUserByEmail
// returns every User whose email matches — we pick the first ACTIVE
// one. Deleted / locked users are ignored here so a recreated account
// under the same email wins.
//
// The directory is backend-agnostic: the same type is wired by the
// DynamoDB and Cosmos DB backends. Only the UserClient construction
// (and thus the underlying OpaqueStore) differs.
type OpaqueDirectory struct {
	client *userv1.UserClient
}

// NewOpaqueDirectory constructs a [service.UserDirectory] backed by
// the User aggregate's email GSI query on the given UserClient.
func NewOpaqueDirectory(client *userv1.UserClient) *OpaqueDirectory {
	return &OpaqueDirectory{client: client}
}

func (d *OpaqueDirectory) FindByEmail(ctx context.Context, email string) (string, error) {
	users, err := d.client.SelectUserByEmail(ctx, email)
	if err != nil {
		return "", fmt.Errorf("OpaqueDirectory: query by email: %w", err)
	}
	for _, u := range users {
		if u.GetState() == userv1.State_STATE_ACTIVE {
			return u.GetId(), nil
		}
	}
	return "", service.ErrDirectoryNotFound
}

var _ service.UserDirectory = (*OpaqueDirectory)(nil)
