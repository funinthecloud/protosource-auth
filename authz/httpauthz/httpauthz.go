// Package httpauthz is the client-side implementation of
// [protosource/authz.Authorizer] that dereferences shadow tokens against
// a running protosource-auth service over HTTP.
//
// Downstream application wiring replaces
// [protosource/authz/allowall.ProviderSet] with [ProviderSet] (or
// constructs an [Authorizer] directly) to route every generated
// command handler's authorization check through the auth service:
//
//	wire.Build(
//	    ...
//	    httpauthz.ProviderSet,
//	    httpauthz.NewAuthorizerFromBaseURL("https://auth.example.com"),
//	    ...
//	)
//
// The authorizer extracts the shadow token from the incoming request
// (Authorization header by default, cookie or custom source configurable),
// posts it to /authz/check, and on success enriches the returned context
// with the authenticated user id and forwarded JWT via
// [protosource/authz.WithUserID] and [protosource/authz.WithJWT].
package httpauthz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/service"
)

// DefaultTimeout is the per-request timeout applied to /authz/check calls
// when the caller does not override it via [WithHTTPClient].
const DefaultTimeout = 5 * time.Second

// DefaultCheckPath is the path the Authorizer POSTs to under baseURL.
const DefaultCheckPath = "/authz/check"

// TokenSource extracts a shadow-token string from an incoming
// [protosource.Request]. Returning "" means "no token present" and causes
// the Authorizer to reject the call with [authz.ErrUnauthenticated]
// without making a network round-trip.
type TokenSource func(req protosource.Request) string

// AuthorizationHeader returns a TokenSource that reads the Authorization
// header, expects a "Bearer " prefix, and returns the token that follows.
// Case-insensitive on the header name since protosource.Request headers
// are stored as-is from the adapter layer.
func AuthorizationHeader() TokenSource {
	return func(req protosource.Request) string {
		for _, key := range []string{"Authorization", "authorization"} {
			if v, ok := req.Headers[key]; ok {
				const prefix = "Bearer "
				if strings.HasPrefix(v, prefix) {
					return strings.TrimPrefix(v, prefix)
				}
			}
		}
		return ""
	}
}

// Cookie returns a TokenSource that reads a named cookie from the Cookie
// header. Handles the multi-cookie "a=1; b=2; c=3" form without depending
// on net/http.Request.
func Cookie(name string) TokenSource {
	return func(req protosource.Request) string {
		for _, headerKey := range []string{"Cookie", "cookie"} {
			raw, ok := req.Headers[headerKey]
			if !ok {
				continue
			}
			for _, part := range strings.Split(raw, ";") {
				part = strings.TrimSpace(part)
				eq := strings.IndexByte(part, '=')
				if eq <= 0 {
					continue
				}
				if part[:eq] == name {
					return part[eq+1:]
				}
			}
		}
		return ""
	}
}

// Chain returns a TokenSource that tries each source in order and
// returns the first non-empty token. Typical use: fall back from a
// cookie to an Authorization header (or vice versa) depending on how
// the downstream service's clients present credentials.
func Chain(sources ...TokenSource) TokenSource {
	return func(req protosource.Request) string {
		for _, s := range sources {
			if tok := s(req); tok != "" {
				return tok
			}
		}
		return ""
	}
}

// Authorizer is the concrete [authz.Authorizer] implementation backed by
// an HTTP call to a protosource-auth service.
type Authorizer struct {
	baseURL     string
	checkPath   string
	httpClient  *http.Client
	tokenSource TokenSource
}

// Option mutates an Authorizer at construction time.
type Option func(*Authorizer)

// WithHTTPClient replaces the default http.Client. Use to inject
// timeouts, retries, transports, or test doubles.
func WithHTTPClient(c *http.Client) Option {
	return func(a *Authorizer) { a.httpClient = c }
}

// WithTokenSource replaces the default Authorization-header token source.
// Use [Chain] to combine multiple sources.
func WithTokenSource(src TokenSource) Option {
	return func(a *Authorizer) { a.tokenSource = src }
}

// WithCheckPath overrides the path appended to baseURL for check calls.
// Defaults to [DefaultCheckPath].
func WithCheckPath(p string) Option {
	return func(a *Authorizer) { a.checkPath = p }
}

// New constructs an Authorizer pointing at baseURL. baseURL must include
// the scheme ("https://auth.example.com"); no trailing slash is
// required. Defaults: 5-second timeout, Authorization-header token
// source, /authz/check path.
func New(baseURL string, opts ...Option) *Authorizer {
	if baseURL == "" {
		panic("httpauthz.New: baseURL must not be empty")
	}
	a := &Authorizer{
		baseURL:     strings.TrimRight(baseURL, "/"),
		checkPath:   DefaultCheckPath,
		httpClient:  &http.Client{Timeout: DefaultTimeout},
		tokenSource: AuthorizationHeader(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Authorize implements [authz.Authorizer]. It extracts the shadow token,
// calls the auth service's check endpoint, and on success returns a
// context carrying the authenticated user id and forwarded JWT.
//
// Error mapping:
//
//	HTTP 401 → authz.ErrUnauthenticated
//	HTTP 403 → authz.ErrForbidden
//	other    → a wrapped error (the generated handler treats this
//	           conservatively as forbidden)
//	missing token (source returned "") → authz.ErrUnauthenticated
//	                                     (no round-trip)
func (a *Authorizer) Authorize(ctx context.Context, req protosource.Request, requiredFunction string) (context.Context, error) {
	token := a.tokenSource(req)
	if token == "" {
		return ctx, authz.ErrUnauthenticated
	}

	body := service.CheckRequestJSON{
		Token:            token,
		RequiredFunction: requiredFunction,
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return ctx, fmt.Errorf("httpauthz: marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+a.checkPath, bytes.NewReader(bodyBytes))
	if err != nil {
		return ctx, fmt.Errorf("httpauthz: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return ctx, fmt.Errorf("httpauthz: check request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var out service.CheckResponseJSON
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return ctx, fmt.Errorf("httpauthz: decode response: %w", err)
		}
		ctx = authz.WithUserID(ctx, out.UserID)
		if out.JWT != "" {
			ctx = authz.WithJWT(ctx, out.JWT)
		}
		return ctx, nil

	case http.StatusUnauthorized:
		// Drain the body to keep keep-alive healthy.
		_, _ = io.Copy(io.Discard, resp.Body)
		return ctx, authz.ErrUnauthenticated

	case http.StatusForbidden:
		_, _ = io.Copy(io.Discard, resp.Body)
		return ctx, authz.ErrForbidden

	default:
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return ctx, fmt.Errorf("httpauthz: unexpected status %d: %s", resp.StatusCode, bytes.TrimSpace(snippet))
	}
}

// Compile-time assertion that Authorizer satisfies [authz.Authorizer].
var _ authz.Authorizer = (*Authorizer)(nil)
