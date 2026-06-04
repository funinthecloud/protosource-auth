package app

import (
	"strings"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/authz/directauthz"
	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/loginpage"
	"github.com/funinthecloud/protosource-auth/service"
)

// NewRouter constructs the full protosource-auth router from a normalized
// Config + Bundle + key Resolver. Both the standalone HTTP binary and
// the Lambda entry point call this so the registered route set + CORS
// posture stay identical across deployments.
//
// When bundle.UserClient is nil (memory backend — see [Bundle]) the
// router is reduced to the minimum useful set: POST /login,
// POST /authz/check, the login page at /, the OIDC discovery document
// at /.well-known/openid-configuration, and the real /oauth/jwks
// endpoint (plus committed /oauth/* stub paths per V2_FEDERATION.md
// so v2 does not force consumer rewiring). The v1 admin handlers need
// a UserClient to back their materialized reads, so omitting them is
// the honest choice rather than registering routes that would 500 on
// every read.
//
// CORS is applied when cfg.CORSOrigin is non-empty, with credentials
// always allowed so the (cfg.ShadowCookieName) cookie flows on cross-origin XHR from
// the admin SPA. An empty CORSOrigin leaves CORS disabled — same-
// origin deployments (admin SPA and API on one host) need no headers
// and benefit from a smaller preflight surface.
func NewRouter(cfg *Config, bundle *Bundle, resolver *keys.Resolver) *protosource.Router {
	loginer := service.NewLoginer(
		bundle.UserRepo, bundle.IssuerRepo, bundle.TokenRepo,
		bundle.Directory, resolver,
		service.WithTokenTTL(cfg.TokenTTL),
	)
	checker := service.NewChecker(bundle.TokenRepo, bundle.UserRepo, bundle.RoleRepo)
	svc := service.NewService(loginer, checker)
	lp := loginpage.New(cfg.IssuerID, cfg.ShadowCookieName, loginer)
	disc := service.NewDiscovery(cfg.IssuerIss, cfg.ShadowCookieName)
	jwks := service.NewJWKS(resolver, cfg.IssuerID)

	registrars := []protosource.RouteRegistrar{svc, lp, disc, jwks}

	// The v1 admin handlers + whoami + adminUser require the
	// opaquedata-backed clients. Memory backend leaves them nil; see
	// [Bundle]. Skip registration so the memory binary still serves
	// the minimal login/check surface used by tests.
	if bundle.UserClient != nil {
		authorizer := buildAuthorizer(checker, cfg.ShadowCookieName)
		whoami := service.NewWhoami(bundle.TokenRepo, bundle.UserRepo, cfg.ShadowCookieName)
		adminUser := service.NewAdminUser(bundle.UserRepo, authorizer)

		registrars = append(registrars,
			whoami,
			adminUser,
			userv1.NewHandler(bundle.UserRepo, bundle.UserClient, authorizer),
			rolev1.NewHandler(bundle.RoleRepo, bundle.RoleClient, authorizer),
			issuerv1.NewHandler(bundle.IssuerRepo, bundle.IssuerClient, authorizer),
			keyv1.NewHandler(bundle.KeyRepo, bundle.KeyClient, authorizer),
			tokenv1.NewHandler(bundle.TokenRepo, bundle.TokenClient, authorizer),
		)
	}

	r := protosource.NewRouter(registrars...)
	if origins := splitOrigins(cfg.CORSOrigin); len(origins) > 0 {
		r.SetCORS(protosource.CORSConfig{
			AllowOrigins:     origins,
			AllowMethods:     "GET,POST,OPTIONS",
			AllowHeaders:     "Content-Type,Accept",
			AllowCredentials: true,
		})
	}
	return r
}

// buildAuthorizer constructs the in-process authorizer used by the
// admin handlers. Cookie token source matches what the SPA sends —
// the loginpage sets cfg.ShadowCookieName on successful POST /.
func buildAuthorizer(checker *service.Checker, cookieName string) authz.Authorizer {
	if cookieName == "" {
		cookieName = "shadow"
	}
	return directauthz.New(checker,
		directauthz.WithTokenSource(httpauthz.Cookie(cookieName)),
	)
}

func splitOrigins(raw string) []string {
	out := make([]string, 0)
	for _, part := range strings.Split(raw, ",") {
		if s := strings.TrimSpace(part); s != "" {
			out = append(out, s)
		}
	}
	return out
}
