package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/functions"
)

// Checker dereferences a shadow token and verifies that its user holds a
// required function. It's the server-side implementation of the
// protosource/authz.Authorizer contract — phase 6 will ship an
// httpauthz.Authorizer that speaks to a Checker over HTTP.
//
// The hot path:
//
//  1. Load the Token aggregate by its opaque id. Not-found, expired, or
//     revoked tokens return authz.ErrUnauthenticated.
//  2. Consult the in-process function cache keyed by user id. On hit,
//     skip to the match step.
//  3. On miss, load the User, fan out to load each assigned Role, take
//     the union of their function strings, and cache the result.
//  4. Match the required function against the function set using the
//     wildcard rules in the functions package. No match returns
//     authz.ErrForbidden.
type Checker struct {
	tokenRepo AggregateRepo
	userRepo  AggregateRepo
	roleRepo  AggregateRepo

	cache *functionCache
	clock func() time.Time
}

// CheckerOption mutates a Checker at construction time.
type CheckerOption func(*Checker)

// WithCheckerClock replaces the checker's time source.
func WithCheckerClock(clock func() time.Time) CheckerOption {
	return func(c *Checker) { c.clock = clock }
}

// WithCacheTTL overrides the function-cache staleness window.
func WithCacheTTL(ttl time.Duration) CheckerOption {
	return func(c *Checker) { c.cache.ttl = ttl }
}

// NewChecker wires a Checker with its dependencies. All three repos are
// required; passing nil panics with a descriptive message.
func NewChecker(
	tokenRepo AggregateRepo,
	userRepo AggregateRepo,
	roleRepo AggregateRepo,
	opts ...CheckerOption,
) *Checker {
	if tokenRepo == nil {
		panic("service.NewChecker: tokenRepo must not be nil")
	}
	if userRepo == nil {
		panic("service.NewChecker: userRepo must not be nil")
	}
	if roleRepo == nil {
		panic("service.NewChecker: roleRepo must not be nil")
	}
	c := &Checker{
		tokenRepo: tokenRepo,
		userRepo:  userRepo,
		roleRepo:  roleRepo,
		clock:     time.Now,
	}
	c.cache = newFunctionCache(DefaultFunctionCacheTTL, func() time.Time { return c.clock() })
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// CheckRequest is the input to [Checker.Check].
type CheckRequest struct {
	// Token is the opaque shadow-token value the caller presented
	// (cookie or Authorization header, extracted by the HTTP adapter).
	Token string
	// RequiredFunction is the canonical "{proto_package}.{MessageName}"
	// function string the downstream service needs — stamped into the
	// generated handler at code-generation time.
	RequiredFunction string
}

// CheckResponse is the output of a successful [Checker.Check].
type CheckResponse struct {
	// UserID is the authenticated user — the subject of the JWT.
	UserID string
	// JWT is the full signed JWT cached on the Token aggregate. The
	// downstream service may forward it as an Authorization header on
	// outbound calls so other services can verify it offline via JWKS.
	JWT string
}

// Check dereferences the shadow token and verifies authorization. The
// error sentinels map to HTTP 401 and 403 respectively (the generated
// handler's authzErrorResponse does the mapping).
func (c *Checker) Check(ctx context.Context, req CheckRequest) (*CheckResponse, error) {
	if req.Token == "" || req.RequiredFunction == "" {
		return nil, authz.ErrUnauthenticated
	}

	tokenAgg, err := c.tokenRepo.Load(ctx, req.Token)
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			return nil, authz.ErrUnauthenticated
		}
		return nil, fmt.Errorf("service: load token: %w", err)
	}
	token, ok := tokenAgg.(*tokenv1.Token)
	if !ok {
		return nil, fmt.Errorf("service: loaded token is %T, want *tokenv1.Token", tokenAgg)
	}
	if token.GetState() != tokenv1.State_STATE_ISSUED {
		return nil, authz.ErrUnauthenticated
	}
	if token.GetExpiresAt() > 0 && c.clock().Unix() >= token.GetExpiresAt() {
		return nil, authz.ErrUnauthenticated
	}

	userID := token.GetUserId()

	functionSet, hit := c.cache.get(userID)
	var diag resolveDiag
	if !hit {
		functionSet, diag, err = c.resolveFunctions(ctx, userID)
		if err != nil {
			return nil, err
		}
		c.cache.put(userID, functionSet)
	}

	if !functions.MatchAny(functionSet, req.RequiredFunction) {
		attrs := []any{
			"code", "AUTHZ_FORBIDDEN",
			"user_id", userID,
			"required_function", req.RequiredFunction,
			"granted_functions", functionSet,
			"granted_count", len(functionSet),
			"cache_hit", hit,
		}
		if !hit {
			attrs = append(attrs,
				"role_ids", diag.roleIDs,
				"role_count", len(diag.roleIDs),
				"skipped_missing_roles", diag.skippedMissing,
				"skipped_inactive_roles", diag.skippedInactive,
			)
		}
		slog.WarnContext(ctx, "authz: forbidden", attrs...)
		return nil, authz.ErrForbidden
	}

	return &CheckResponse{
		UserID: userID,
		JWT:    token.GetJwt(),
	}, nil
}

// Identify dereferences a shadow token to its authenticated user id
// without performing any function-grant check. It applies the same
// liveness gates as [Checker.Check] — token ISSUED + unexpired, user
// loaded + STATE_ACTIVE — so a revoked shadow or a locked/deleted user
// is rejected with [authz.ErrUnauthenticated]. It is the validation
// step behind minting a fresh access JWT from a shadow session (see
// [AccessHandler]): the shadow remains the source of truth for instant
// revocation, re-checked on every refresh.
func (c *Checker) Identify(ctx context.Context, token string) (string, error) {
	if token == "" {
		return "", authz.ErrUnauthenticated
	}

	tokenAgg, err := c.tokenRepo.Load(ctx, token)
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			return "", authz.ErrUnauthenticated
		}
		return "", fmt.Errorf("service: load token: %w", err)
	}
	token0, ok := tokenAgg.(*tokenv1.Token)
	if !ok {
		return "", fmt.Errorf("service: loaded token is %T, want *tokenv1.Token", tokenAgg)
	}
	if token0.GetState() != tokenv1.State_STATE_ISSUED {
		return "", authz.ErrUnauthenticated
	}
	if token0.GetExpiresAt() > 0 && c.clock().Unix() >= token0.GetExpiresAt() {
		return "", authz.ErrUnauthenticated
	}

	userID := token0.GetUserId()
	userAgg, err := c.userRepo.Load(ctx, userID)
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			return "", authz.ErrUnauthenticated
		}
		return "", fmt.Errorf("service: load user: %w", err)
	}
	user, ok := userAgg.(*userv1.User)
	if !ok {
		return "", fmt.Errorf("service: loaded user is %T, want *userv1.User", userAgg)
	}
	if user.GetState() != userv1.State_STATE_ACTIVE {
		return "", authz.ErrUnauthenticated
	}
	return userID, nil
}

// resolveDiag captures information about how a function set was built so
// callers can surface it in diagnostic logs (especially on forbidden).
type resolveDiag struct {
	roleIDs         []string
	skippedMissing  []string
	skippedInactive []string
}

// resolveFunctions walks User → Roles → FunctionGrants and returns the
// deduplicated union of function strings.
func (c *Checker) resolveFunctions(ctx context.Context, userID string) ([]string, resolveDiag, error) {
	var diag resolveDiag
	userAgg, err := c.userRepo.Load(ctx, userID)
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			// Token references a user that no longer exists. Treat as
			// unauthenticated rather than forbidden — the identity is
			// gone, not the authorization.
			return nil, diag, authz.ErrUnauthenticated
		}
		return nil, diag, fmt.Errorf("service: load user: %w", err)
	}
	user, ok := userAgg.(*userv1.User)
	if !ok {
		return nil, diag, fmt.Errorf("service: loaded user is %T, want *userv1.User", userAgg)
	}

	if user.GetState() != userv1.State_STATE_ACTIVE {
		// Locked, deleted, or pending — revoke access regardless of what
		// the token says.
		return nil, diag, authz.ErrUnauthenticated
	}

	diag.roleIDs = make([]string, 0, len(user.GetRoles()))
	for roleID := range user.GetRoles() {
		diag.roleIDs = append(diag.roleIDs, roleID)
	}

	seen := make(map[string]struct{})
	var out []string
	for _, roleID := range diag.roleIDs {
		roleAgg, err := c.roleRepo.Load(ctx, roleID)
		if err != nil {
			if errors.Is(err, protosource.ErrAggregateNotFound) {
				// Role was deleted after assignment. Skip silently — the
				// user just loses that role's grants.
				diag.skippedMissing = append(diag.skippedMissing, roleID)
				continue
			}
			return nil, diag, fmt.Errorf("service: load role %q: %w", roleID, err)
		}
		role, ok := roleAgg.(*rolev1.Role)
		if !ok {
			return nil, diag, fmt.Errorf("service: loaded role is %T, want *rolev1.Role", roleAgg)
		}
		if role.GetState() != rolev1.State_STATE_ACTIVE {
			diag.skippedInactive = append(diag.skippedInactive, roleID)
			continue
		}
		for fn := range role.GetFunctions() {
			if _, dup := seen[fn]; dup {
				continue
			}
			seen[fn] = struct{}{}
			out = append(out, fn)
		}
	}

	return out, diag, nil
}
