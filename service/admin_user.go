package service

import (
	"context"
	"encoding/json"
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
	Actor    string `json:"actor"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *AdminUser) handleCreate(ctx context.Context, req protosource.Request) protosource.Response {
	if _, err := a.authorizer.Authorize(ctx, req, "admin.user.v1.Create"); err != nil {
		return adminError(http.StatusUnauthorized, "unauthorized")
	}

	var in adminCreateRequest
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return adminError(http.StatusBadRequest, "invalid request body")
	}
	if in.ID == "" || in.Email == "" || in.Password == "" || in.Actor == "" {
		return adminError(http.StatusBadRequest, "id, actor, email, and password are required")
	}

	hash, err := credentials.Hash(in.Password)
	if err != nil {
		return adminError(http.StatusInternalServerError, "failed to hash password")
	}

	if _, err := a.userRepo.Apply(ctx, &userv1.Create{
		Id:           in.ID,
		Actor:        in.Actor,
		Email:        in.Email,
		PasswordHash: hash,
	}); err != nil {
		return adminError(http.StatusConflict, err.Error())
	}

	return adminJSON(http.StatusCreated, map[string]string{"id": in.ID})
}

type adminChangePasswordRequest struct {
	ID       string `json:"id"`
	Actor    string `json:"actor"`
	Password string `json:"password"`
}

func (a *AdminUser) handleChangePassword(ctx context.Context, req protosource.Request) protosource.Response {
	if _, err := a.authorizer.Authorize(ctx, req, "admin.user.v1.ChangePassword"); err != nil {
		return adminError(http.StatusUnauthorized, "unauthorized")
	}

	var in adminChangePasswordRequest
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return adminError(http.StatusBadRequest, "invalid request body")
	}
	if in.ID == "" || in.Password == "" || in.Actor == "" {
		return adminError(http.StatusBadRequest, "id, actor, and password are required")
	}

	hash, err := credentials.Hash(in.Password)
	if err != nil {
		return adminError(http.StatusInternalServerError, "failed to hash password")
	}

	if _, err := a.userRepo.Apply(ctx, &userv1.ChangePassword{
		Id:           in.ID,
		Actor:        in.Actor,
		PasswordHash: hash,
	}); err != nil {
		return adminError(http.StatusConflict, err.Error())
	}

	return adminJSON(http.StatusOK, map[string]string{"ok": "true"})
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
