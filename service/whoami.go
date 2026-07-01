package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/funinthecloud/protosource"

	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/internal/httputil"
)

// Whoami serves GET /whoami, returning the authenticated user's identity
// derived from the (configurable) shadow cookie. The frontend uses it to
// detect login state and to obtain the user_id for the actor field on commands.
// Cookie name is configurable for v2 federation (see ShadowCookieName in app.Config).
type Whoami struct {
	tokenRepo  AggregateRepo
	userRepo   AggregateRepo
	cookieName string
	clock      func() time.Time
}

// WhoamiOption configures a Whoami at construction time.
type WhoamiOption func(*Whoami)

// WithWhoamiClock replaces the default time source (for tests).
func WithWhoamiClock(clock func() time.Time) WhoamiOption {
	return func(w *Whoami) { w.clock = clock }
}

// NewWhoami constructs a Whoami handler. Both repos are required.
// cookieName defaults to "shadow" if empty.
func NewWhoami(tokenRepo, userRepo AggregateRepo, cookieName string, opts ...WhoamiOption) *Whoami {
	if tokenRepo == nil {
		panic("service.NewWhoami: tokenRepo must not be nil")
	}
	if userRepo == nil {
		panic("service.NewWhoami: userRepo must not be nil")
	}
	if cookieName == "" {
		cookieName = "shadow"
	}
	w := &Whoami{
		tokenRepo:  tokenRepo,
		userRepo:   userRepo,
		cookieName: cookieName,
		clock:      time.Now,
	}
	for _, opt := range opts {
		opt(w)
	}
	return w
}

// RegisterRoutes registers GET /whoami on the router.
func (w *Whoami) RegisterRoutes(router *protosource.Router) {
	router.Handle("GET", "/whoami", w.handle)
}

// whoamiResponse is the JSON wire shape returned by GET /whoami.
type whoamiResponse struct {
	UserID string                `json:"user_id"`
	Email  string                `json:"email"`
	Roles  map[string]whoamiRole `json:"roles"`
}

type whoamiRole struct {
	RoleID     string `json:"role_id"`
	AssignedAt int64  `json:"assigned_at"`
}

func (w *Whoami) handle(ctx context.Context, req protosource.Request) protosource.Response {
	token := httputil.CookieValue(req, w.cookieName)
	if token == "" {
		return whoamiError(http.StatusUnauthorized, "unauthenticated")
	}

	tokenAgg, err := w.tokenRepo.Load(ctx, token)
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			return whoamiError(http.StatusUnauthorized, "unauthenticated")
		}
		return whoamiError(http.StatusServiceUnavailable, "service unavailable")
	}
	tok, ok := tokenAgg.(*tokenv1.Token)
	if !ok {
		return whoamiError(http.StatusServiceUnavailable, "service unavailable")
	}
	if tok.GetState() != tokenv1.State_STATE_ISSUED {
		return whoamiError(http.StatusUnauthorized, "unauthenticated")
	}
	if tok.GetExpiresAt() > 0 && w.clock().Unix() >= tok.GetExpiresAt() {
		return whoamiError(http.StatusUnauthorized, "unauthenticated")
	}

	userAgg, err := w.userRepo.Load(ctx, tok.GetUserId())
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			return whoamiError(http.StatusUnauthorized, "unauthenticated")
		}
		return whoamiError(http.StatusServiceUnavailable, "service unavailable")
	}
	user, ok := userAgg.(*userv1.User)
	if !ok {
		return whoamiError(http.StatusServiceUnavailable, "service unavailable")
	}
	if user.GetState() != userv1.State_STATE_ACTIVE {
		return whoamiError(http.StatusUnauthorized, "unauthenticated")
	}

	roles := make(map[string]whoamiRole, len(user.GetRoles()))
	for k, v := range user.GetRoles() {
		roles[k] = whoamiRole{
			RoleID:     v.GetRoleId(),
			AssignedAt: v.GetAssignedAt(),
		}
	}

	body, err := json.Marshal(whoamiResponse{
		UserID: user.GetId(),
		Email:  user.GetEmail(),
		Roles:  roles,
	})
	if err != nil {
		return whoamiError(http.StatusInternalServerError, "failed to serialize response")
	}
	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

func whoamiError(status int, message string) protosource.Response {
	body, _ := json.Marshal(map[string]string{"error": message})
	return protosource.Response{
		StatusCode: status,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

// Ensure Whoami satisfies RouteRegistrar.
var _ protosource.RouteRegistrar = (*Whoami)(nil)
