// Package directauthz implements [authz.Authorizer] by calling the
// [service.Checker] directly against the aggregate repositories,
// bypassing the HTTP round-trip that [httpauthz.Authorizer] makes.
//
// Use this when the consuming Lambda shares the same DynamoDB tables as
// the protosource-auth service.
package directauthz

import (
	"context"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	"github.com/funinthecloud/protosource-auth/service"
)

// Authorizer implements [authz.Authorizer] by delegating to a
// [service.Checker] in-process. No network round-trip — token
// dereference, user/role loading, and function matching all happen
// via direct DynamoDB reads.
type Authorizer struct {
	checker     *service.Checker
	tokenSource httpauthz.TokenSource
}

// Option configures an Authorizer at construction time.
type Option func(*Authorizer)

// WithTokenSource overrides the default token extraction strategy.
// The default is [httpauthz.AuthorizationHeader].
func WithTokenSource(src httpauthz.TokenSource) Option {
	return func(a *Authorizer) { a.tokenSource = src }
}

// New constructs a direct Authorizer backed by the given Checker.
// The default token source is [httpauthz.AuthorizationHeader].
func New(checker *service.Checker, opts ...Option) *Authorizer {
	if checker == nil {
		panic("directauthz.New: checker must not be nil")
	}
	a := &Authorizer{
		checker:     checker,
		tokenSource: httpauthz.AuthorizationHeader(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Authorize extracts the shadow token from req, delegates to the
// Checker, and enriches the returned context with the authenticated
// user id and forwarded JWT on success.
func (a *Authorizer) Authorize(ctx context.Context, req protosource.Request, requiredFunction string) (context.Context, error) {
	token := a.tokenSource(req)
	if token == "" {
		return ctx, authz.ErrUnauthenticated
	}

	resp, err := a.checker.Check(ctx, service.CheckRequest{
		Token:            token,
		RequiredFunction: requiredFunction,
	})
	if err != nil {
		return ctx, err
	}

	ctx = authz.WithUserID(ctx, resp.UserID)
	if resp.JWT != "" {
		ctx = authz.WithJWT(ctx, resp.JWT)
	}
	return ctx, nil
}

var _ authz.Authorizer = (*Authorizer)(nil)
