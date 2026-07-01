package service

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	"github.com/funinthecloud/protosource-auth/internal/httputil"
)

// AdminIssuer provides the secret-safe admin endpoint the SPA uses to set or
// rotate a KIND_EXTERNAL issuer's OIDC client config. It accepts the plaintext
// client_secret over HTTPS and delegates to [OIDCConfigurator.Set], which
// envelope-encrypts it via the KeyProvider before the SetOIDCConfig command is
// built — so the plaintext secret never reaches the event store, and a blank
// secret preserves the previously wrapped one (an endpoint/policy-only update
// must not clobber stored credentials).
//
// This is the issuer analogue of [AdminUser]: the browser cannot wrap the
// secret (the KeyProvider lives server-side) and must not write raw
// auth.issuer.v1.SetOIDCConfig (whose by-name OIDCConfig embed would overwrite
// wrapped_client_secret with empty bytes). Authorization uses the
// admin.issuer.v1.* function namespace so the raw command can stay ungranted.
// The actor is taken from the authenticated context, never from the client.
type AdminIssuer struct {
	configurator *OIDCConfigurator
	authorizer   authz.Authorizer
}

// NewAdminIssuer constructs an AdminIssuer handler.
func NewAdminIssuer(configurator *OIDCConfigurator, authorizer authz.Authorizer) *AdminIssuer {
	if configurator == nil {
		panic("service.NewAdminIssuer: configurator must not be nil")
	}
	if authorizer == nil {
		panic("service.NewAdminIssuer: authorizer must not be nil")
	}
	return &AdminIssuer{configurator: configurator, authorizer: authorizer}
}

// RegisterRoutes registers the admin issuer endpoints on the router.
func (a *AdminIssuer) RegisterRoutes(router *protosource.Router) {
	router.Handle("POST", "/admin/issuer/setoidc", a.handleSetOIDC)
}

// adminSetOIDCRequest is the wire shape the SPA OIDC form POSTs. Field names
// are snake_case to match the rest of the JSON API. ClientSecret is plaintext
// and write-only: omit it to keep the previously stored secret.
type adminSetOIDCRequest struct {
	IssuerID     string `json:"issuer_id"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`

	DiscoveryURL          string `json:"discovery_url"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`

	AllowedAudiences []string          `json:"allowed_audiences"`
	ClaimMap         map[string]string `json:"claim_map"`

	JITPolicy        issuerv1.OIDCJITPolicy `json:"jit_policy"`
	JITDefaultRoleID string                 `json:"jit_default_role_id"`
	JITDomain        string                 `json:"jit_domain"`
}

func (a *AdminIssuer) handleSetOIDC(ctx context.Context, req protosource.Request) protosource.Response {
	// This endpoint accepts a plaintext client_secret in the body, so it must
	// fail closed on cleartext exactly like /oauth/authorize, /oauth/callback,
	// and /auth/refresh — never let secret material ride over non-HTTPS.
	if !httputil.IsSecure(req) {
		return adminError(http.StatusForbidden, "https_required")
	}

	ctx, err := a.authorizer.Authorize(ctx, req, "admin.issuer.v1.SetOIDCConfig")
	if err != nil {
		return authzError(err)
	}
	actor := authz.UserIDFromContext(ctx)

	var in adminSetOIDCRequest
	if err := json.Unmarshal([]byte(req.Body), &in); err != nil {
		return adminError(http.StatusBadRequest, "invalid request body")
	}
	if in.IssuerID == "" || in.ClientID == "" {
		return adminError(http.StatusBadRequest, "issuer_id and client_id are required")
	}

	var secret []byte
	if in.ClientSecret != "" {
		secret = []byte(in.ClientSecret)
	}

	// Set loads the issuer, rejects non-KIND_EXTERNAL, encrypts the secret (or
	// carries the existing wrapped one forward when secret is nil), and applies
	// SetOIDCConfig. Errors are mapped through applyError; the configurator's
	// KIND_EXTERNAL guard surfaces as a 400 validation-style failure below.
	if err := a.configurator.Set(ctx, SetRequest{
		IssuerID:              in.IssuerID,
		Actor:                 actor,
		ClientID:              in.ClientID,
		ClientSecret:          secret,
		DiscoveryURL:          in.DiscoveryURL,
		AuthorizationEndpoint: in.AuthorizationEndpoint,
		TokenEndpoint:         in.TokenEndpoint,
		JWKSURI:               in.JWKSURI,
		AllowedAudiences:      in.AllowedAudiences,
		ClaimMap:              in.ClaimMap,
		JITPolicy:             in.JITPolicy,
		JITDefaultRoleID:      in.JITDefaultRoleID,
		JITDomain:             in.JITDomain,
	}); err != nil {
		return applyError(ctx, err)
	}

	return adminJSON(http.StatusOK, map[string]string{"id": in.IssuerID})
}

var _ protosource.RouteRegistrar = (*AdminIssuer)(nil)
