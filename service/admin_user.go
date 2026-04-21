package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/credentials"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
)

// AdminUser provides password-safe admin endpoints for the SPA.
// It accepts plaintext passwords, hashes them server-side with argon2id,
// and delegates to the generated aggregate commands. This prevents
// plaintext passwords from ever reaching the event store.
//
// Authorization uses the admin.user.v1.* function namespace so that
// raw auth.user.v1.Create/ChangePassword can remain ungranted.
// The actor on commands is derived from the authenticated context,
// not from client-supplied values.
type AdminUser struct {
	userRepo   AggregateRepo
	authorizer authz.Authorizer
}

// NewAdminUser constructs an AdminUser handler.
func NewAdminUser(userRepo AggregateRepo, authorizer authz.Authorizer) *AdminUser {
	return &AdminUser{userRepo: userRepo, authorizer: authorizer}
}

// RegisterRoutes registers admin user endpoints on the router.
func (a *AdminUser) RegisterRoutes(router *protosource.Router) {
	router.Handle("POST", "/admin/user/create", a.handleCreate)
	router.Handle("POST", "/admin/user/changepassword", a.handleChangePassword)
}

type adminCreateRequest struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *AdminUser) handleCreate(ctx context.Context, req protosource.Request) protosource.Response {
	ctx, err := a.authorizer.Authorize(ctx, req, "admin.user.v1.Create")
	if err != nil {
		return authzError(err)
	}
	actor := authz.UserIDFromContext(ctx)

	var in adminCreateRequest
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return adminError(http.StatusBadRequest, "invalid request body")
	}
	if in.ID == "" || in.Email == "" || in.Password == "" {
		return adminError(http.StatusBadRequest, "id, email, and password are required")
	}

	hash, err := credentials.Hash(in.Password)
	if err != nil {
		slog.ErrorContext(ctx, "admin: hash password", "error", err)
		return adminError(http.StatusInternalServerError, "internal error")
	}

	if _, err := a.userRepo.Apply(ctx, &userv1.Create{
		Id:           in.ID,
		Actor:        actor,
		Email:        in.Email,
		PasswordHash: hash,
	}); err != nil {
		return applyError(ctx, err)
	}

	return adminJSON(http.StatusCreated, map[string]string{"id": in.ID})
}

type adminChangePasswordRequest struct {
	ID       string `json:"id"`
	Password string `json:"password"`
}

func (a *AdminUser) handleChangePassword(ctx context.Context, req protosource.Request) protosource.Response {
	ctx, err := a.authorizer.Authorize(ctx, req, "admin.user.v1.ChangePassword")
	if err != nil {
		return authzError(err)
	}
	actor := authz.UserIDFromContext(ctx)

	var in adminChangePasswordRequest
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return adminError(http.StatusBadRequest, "invalid request body")
	}
	if in.ID == "" || in.Password == "" {
		return adminError(http.StatusBadRequest, "id and password are required")
	}

	hash, err := credentials.Hash(in.Password)
	if err != nil {
		slog.ErrorContext(ctx, "admin: hash password", "error", err)
		return adminError(http.StatusInternalServerError, "internal error")
	}

	if _, err := a.userRepo.Apply(ctx, &userv1.ChangePassword{
		Id:           in.ID,
		Actor:        actor,
		PasswordHash: hash,
	}); err != nil {
		return applyError(ctx, err)
	}

	return adminJSON(http.StatusOK, map[string]string{"ok": "true"})
}

// authzError maps authorization errors to HTTP responses, matching
// the generated handlers' authzErrorResponse pattern.
func authzError(err error) protosource.Response {
	switch {
	case errors.Is(err, authz.ErrUnauthenticated):
		return adminError(http.StatusUnauthorized, "unauthenticated")
	case errors.Is(err, authz.ErrForbidden):
		return adminError(http.StatusForbidden, "forbidden")
	default:
		return adminError(http.StatusServiceUnavailable, "authorization service unavailable")
	}
}

// applyError maps aggregate Apply errors to stable HTTP responses.
func applyError(ctx context.Context, err error) protosource.Response {
	switch {
	case errors.Is(err, protosource.ErrAlreadyCreated):
		return adminError(http.StatusConflict, "already exists")
	case errors.Is(err, protosource.ErrAggregateNotFound),
		errors.Is(err, protosource.ErrNotCreatedYet):
		return adminError(http.StatusNotFound, "not found")
	case errors.Is(err, protosource.ErrStateNotAllowed):
		return adminError(http.StatusConflict, "operation not allowed in current state")
	case errors.Is(err, protosource.ErrValidationFailed):
		return adminError(http.StatusBadRequest, "validation failed")
	default:
		slog.ErrorContext(ctx, "admin: apply command", "error", err)
		return adminError(http.StatusInternalServerError, "internal error")
	}
}

func adminError(status int, message string) protosource.Response {
	body, _ := json.Marshal(map[string]string{"error": message})
	return protosource.Response{
		StatusCode: status,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

func adminJSON(status int, v any) protosource.Response {
	body, _ := json.Marshal(v)
	return protosource.Response{
		StatusCode: status,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

var _ protosource.RouteRegistrar = (*AdminUser)(nil)
