// Package directauthz implements [authz.Authorizer] by calling the
// [service.Checker] directly against the aggregate repositories,
// bypassing the HTTP round-trip that [httpauthz.Authorizer] makes.
//
// Use this when the consuming Lambda shares the same DynamoDB tables as
// the protosource-auth service.
package directauthz

import (
	"context"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
)

// Authorizer implements [authz.Authorizer] by delegating to a
// [service.Checker] in-process. No network round-trip — token
// dereference, user/role loading, and function matching all happen
// via direct DynamoDB reads.
type Authorizer struct {
	checker     *service.Checker
	tokenSource httpauthz.TokenSource

	// Access-token identity (optional, enabled via WithAccessTokenIdentity).
	// resolver verifies an access JWT offline against the SELF issuer's
	// keys; accessSource extracts it from the request; accessAudience, when
	// non-empty, is enforced as the expected "aud".
	resolver       *keys.Resolver
	accessSource   httpauthz.TokenSource
	accessAudience string
	now            func() time.Time
}

// Option configures an Authorizer at construction time.
type Option func(*Authorizer)

// WithTokenSource overrides the default token extraction strategy.
// The default is [httpauthz.AuthorizationHeader].
func WithTokenSource(src httpauthz.TokenSource) Option {
	return func(a *Authorizer) { a.tokenSource = src }
}

// WithClock overrides the time source used by [Authorizer.Identify] to
// check access-JWT expiry. Defaults to time.Now; injectable for tests.
func WithClock(clock func() time.Time) Option {
	return func(a *Authorizer) {
		if clock != nil {
			a.now = clock
		}
	}
}

// WithAccessTokenIdentity enables the [Authorizer.Identify] fast path:
// an in-process, offline verification of a short-lived access JWT
// (against resolver's SELF-issuer keys) for callers that need only the
// authenticated user id without a function-grant check. accessSource
// extracts the access JWT from the request (e.g.
// httpauthz.Cookie("shadow_access") or httpauthz.AuthorizationHeader());
// audience, when non-empty, is enforced as the expected "aud".
//
// This does NOT change [Authorizer.Authorize], which still dereferences
// the shadow token and enforces the function grant — function-protected
// calls always require shadow + the full check. Identify is a separate
// capability for identity-only needs.
func WithAccessTokenIdentity(resolver *keys.Resolver, accessSource httpauthz.TokenSource, audience string) Option {
	return func(a *Authorizer) {
		a.resolver = resolver
		a.accessSource = accessSource
		a.accessAudience = audience
	}
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
		now:         time.Now,
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

// Identify verifies a short-lived access JWT offline (no shadow lookup,
// no /authz/check) and returns a context enriched with the authenticated
// user id. It is for endpoints that need only *who* the caller is, not
// *what they may do* — function-grant authorization still belongs to
// [Authorizer.Authorize] (shadow + check).
//
// Requires [WithAccessTokenIdentity]; without it Identify always returns
// [authz.ErrUnauthenticated]. A missing, malformed, expired, wrong-aud,
// or non-access-token JWT also returns [authz.ErrUnauthenticated]
// (fail-closed). The access JWT is verified against the SELF issuer's
// keys via [service.VerifyAccessToken].
func (a *Authorizer) Identify(ctx context.Context, req protosource.Request) (context.Context, error) {
	if a.resolver == nil || a.accessSource == nil {
		return ctx, authz.ErrUnauthenticated
	}
	raw := a.accessSource(req)
	if raw == "" {
		return ctx, authz.ErrUnauthenticated
	}
	claims, err := service.VerifyAccessToken(ctx, a.resolver, raw, a.accessAudience, a.now())
	if err != nil {
		return ctx, authz.ErrUnauthenticated
	}
	return authz.WithUserID(ctx, claims.Subject), nil
}

var _ authz.Authorizer = (*Authorizer)(nil)
