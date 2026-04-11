package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"
)

// Service bundles the hand-written orchestration endpoints and exposes
// them as a [protosource.RouteRegistrar]. Wire a Service alongside the
// generated aggregate Handlers to register /login and /authz/check:
//
//	svc := service.NewService(loginer, checker)
//	router := protosource.NewRouter(svc, userHandler, roleHandler, issuerHandler, keyHandler, tokenHandler)
type Service struct {
	loginer *Loginer
	checker *Checker
}

// NewService wraps a Loginer + Checker pair in a RouteRegistrar. Both
// dependencies are required.
func NewService(loginer *Loginer, checker *Checker) *Service {
	if loginer == nil {
		panic("service.NewService: loginer must not be nil")
	}
	if checker == nil {
		panic("service.NewService: checker must not be nil")
	}
	return &Service{loginer: loginer, checker: checker}
}

// RegisterRoutes wires the login and authz/check endpoints into router.
//
// Routes:
//
//	POST /login         — credential-verify + token-issue
//	POST /authz/check   — dereference shadow token + check required function
func (s *Service) RegisterRoutes(router *protosource.Router) {
	router.Handle("POST", "/login", s.HandleLogin)
	router.Handle("POST", "/authz/check", s.HandleCheck)
}

// ── JSON wire shapes ──

type loginRequestJSON struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Issuer   string `json:"issuer"`
}

type loginResponseJSON struct {
	ShadowToken string `json:"shadow_token"`
	JWT         string `json:"jwt,omitempty"`
	ExpiresAt   int64  `json:"expires_at"`
}

// CheckRequestJSON is the wire shape accepted by POST /authz/check. It is
// exported so [httpauthz.Authorizer] in a sibling package can marshal the
// exact same structure without duplicating field names.
type CheckRequestJSON struct {
	Token            string `json:"token"`
	RequiredFunction string `json:"required_function"`
}

// CheckResponseJSON is the wire shape returned by a successful POST
// /authz/check. Exported alongside [CheckRequestJSON] for client reuse.
type CheckResponseJSON struct {
	UserID string `json:"user_id"`
	JWT    string `json:"jwt,omitempty"`
}

type errorJSON struct {
	Error string `json:"error"`
	Code  string `json:"code,omitempty"`
}

// ── Handlers ──

// HandleLogin validates credentials and returns a freshly issued shadow
// token + signed JWT. See [Loginer.Login] for the domain logic.
func (s *Service) HandleLogin(ctx context.Context, req protosource.Request) protosource.Response {
	var in loginRequestJSON
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return jsonError(http.StatusBadRequest, "LOGIN_BAD_BODY", "invalid request body")
	}
	if in.Email == "" || in.Password == "" || in.Issuer == "" {
		return jsonError(http.StatusBadRequest, "LOGIN_MISSING_FIELD", "email, password, and issuer are required")
	}

	out, err := s.loginer.Login(ctx, LoginRequest{
		Email:    in.Email,
		Password: in.Password,
		IssuerID: in.Issuer,
	})
	if err != nil {
		return loginErrorResponse(err)
	}

	return jsonOK(loginResponseJSON{
		ShadowToken: out.ShadowToken,
		JWT:         out.JWT,
		ExpiresAt:   out.ExpiresAt,
	})
}

// HandleCheck dereferences a shadow token and verifies that its user
// holds the required function. See [Checker.Check] for the domain logic.
func (s *Service) HandleCheck(ctx context.Context, req protosource.Request) protosource.Response {
	var in CheckRequestJSON
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return jsonError(http.StatusBadRequest, "CHECK_BAD_BODY", "invalid request body")
	}
	if in.Token == "" || in.RequiredFunction == "" {
		return jsonError(http.StatusBadRequest, "CHECK_MISSING_FIELD", "token and required_function are required")
	}

	out, err := s.checker.Check(ctx, CheckRequest{
		Token:            in.Token,
		RequiredFunction: in.RequiredFunction,
	})
	if err != nil {
		return checkErrorResponse(err)
	}

	return jsonOK(CheckResponseJSON{
		UserID: out.UserID,
		JWT:    out.JWT,
	})
}

// ── Error mapping ──

// loginErrorResponse maps Loginer errors to HTTP responses. Unknown
// errors are mapped to 503 (not 500) so clients, load balancers, and
// monitoring distinguish "the auth service is having a transient
// problem" from "your credentials are wrong" — same fail-closed
// reasoning as the framework's authzErrorResponse.
func loginErrorResponse(err error) protosource.Response {
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return jsonError(http.StatusUnauthorized, "LOGIN_INVALID_CREDENTIALS", "invalid credentials")
	case errors.Is(err, ErrUserNotActive):
		return jsonError(http.StatusForbidden, "LOGIN_USER_NOT_ACTIVE", "user account is not active")
	case errors.Is(err, ErrIssuerNotActive):
		return jsonError(http.StatusServiceUnavailable, "LOGIN_ISSUER_NOT_ACTIVE", "issuer is not active or not configured for signing")
	default:
		return jsonError(http.StatusServiceUnavailable, "LOGIN_UNAVAILABLE", "login service unavailable")
	}
}

// checkErrorResponse maps Checker errors to HTTP responses. Unknown
// errors map to 503 for the same retry/alerting reason — a transient
// store failure must not look like a permission denial to the
// downstream caller.
func checkErrorResponse(err error) protosource.Response {
	switch {
	case errors.Is(err, authz.ErrUnauthenticated):
		return jsonError(http.StatusUnauthorized, "CHECK_UNAUTHENTICATED", "unauthenticated")
	case errors.Is(err, authz.ErrForbidden):
		return jsonError(http.StatusForbidden, "CHECK_FORBIDDEN", "forbidden")
	default:
		return jsonError(http.StatusServiceUnavailable, "CHECK_UNAVAILABLE", "authorization service unavailable")
	}
}

func jsonOK(body any) protosource.Response {
	b, err := json.Marshal(body)
	if err != nil {
		return jsonError(http.StatusInternalServerError, "MARSHAL", "failed to serialize response")
	}
	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       string(b),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

func jsonError(status int, code, message string) protosource.Response {
	b, _ := json.Marshal(errorJSON{Error: message, Code: code})
	return protosource.Response{
		StatusCode: status,
		Body:       string(b),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}
