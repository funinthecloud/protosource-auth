package app

import (
	"log/slog"
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
	"github.com/funinthecloud/protosource-auth/keyproviders"
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
func NewRouter(cfg *Config, bundle *Bundle, resolver *keys.Resolver, provider keyproviders.KeyProvider, masterKeyRef string) *protosource.Router {
	loginer := service.NewLoginer(
		bundle.UserRepo, bundle.IssuerRepo, bundle.TokenRepo,
		bundle.Directory, resolver,
		service.WithTokenTTL(cfg.TokenTTL),
		service.WithAccessTTL(cfg.AccessTokenTTL),
		service.WithAccessAudience(cfg.AccessAudience),
	)
	checker := service.NewChecker(bundle.TokenRepo, bundle.UserRepo, bundle.RoleRepo)
	svc := service.NewService(loginer, checker)
	lp := loginpage.New(cfg.IssuerID, cfg.ShadowCookieName, cfg.AccessCookieName, loginer)
	// POST /auth/refresh: exchange the live shadow cookie for a fresh
	// short-lived access-JWT cookie (the browser's silent-refresh path).
	accessRefresh := service.NewAccessHandler(
		checker, loginer,
		cfg.IssuerID, cfg.ShadowCookieName, cfg.AccessCookieName,
	)
	disc := service.NewDiscovery(cfg.IssuerIss, cfg.ShadowCookieName)
	jwks := service.NewJWKS(resolver, cfg.IssuerID)

	// Federated-login PKCE flow (GET /oauth/authorize + /oauth/callback).
	// The OIDCConfigurator reuses the same KeyProvider as the key resolver
	// to decrypt IdP client secrets at callback time.
	configurator := service.NewOIDCConfigurator(bundle.IssuerRepo, provider, masterKeyRef)
	// Federated identity resolution (Phase 2): deterministic-id JIT provisioning
	// backed by an in-memory link index. JIT_AUTO_NO_ROLES and JIT_DOMAIN_RULE
	// work today — deterministic User ids + Create/ErrAlreadyCreated convergence
	// recognize returning users even with a cold index. JIT_REJECT recognition of
	// pre-linked users with arbitrary ids requires the persistent link-index GSI
	// (protosource-auth-i1z); until it lands, REJECT-policy issuers recognize
	// only links seen by this instance since start (fail-closed otherwise).
	linkDir := service.NewMapLinkDirectory()
	identityResolver := service.NewIdentityProvisioner(bundle.UserRepo, linkDir)
	if bundle.UserClient != nil {
		// Persistent backend (DynamoDB/Cosmos), but the federated link index is
		// still in-memory and starts cold on every restart. That makes
		// JIT_REJECT — the default policy — a quiet operational footgun: an
		// already-linked user can be rejected after a restart simply because
		// this instance has not re-observed their link. Surface it loudly at
		// startup rather than letting it ship silently. The durable fix is the
		// link-index GSI projection (protosource-auth-i1z); see
		// service.MapLinkDirectory for the full contract.
		slog.Warn("federated link index is in-memory on a persistent backend: "+
			"JIT_REJECT issuers will not recognize pre-linked users across process restarts "+
			"until the link-index GSI lands; AUTO/DOMAIN policies are unaffected",
			"code", "FEDERATION_LINK_INDEX_EPHEMERAL",
			"followup", "protosource-auth-i1z",
		)
	}
	oauthHandler := service.NewOAuthHandler(
		bundle.IssuerRepo, configurator, resolver, loginer,
		identityResolver,
		cfg.IssuerID, cfg.IssuerIss, cfg.ShadowCookieName,
		service.WithOAuthAccessCookieName(cfg.AccessCookieName),
	)

	registrars := []protosource.RouteRegistrar{svc, lp, disc, jwks, oauthHandler, accessRefresh}

	// The v1 admin handlers + whoami + adminUser require the
	// opaquedata-backed clients. Memory backend leaves them nil; see
	// [Bundle]. Skip registration so the memory binary still serves
	// the minimal login/check surface used by tests.
	if bundle.UserClient != nil {
		authorizer := buildAuthorizer(checker, cfg.ShadowCookieName)
		whoami := service.NewWhoami(bundle.TokenRepo, bundle.UserRepo, cfg.ShadowCookieName)
		adminUser := service.NewAdminUser(bundle.UserRepo, authorizer)
		// Secret-safe OIDC config intake for the admin SPA: takes the plaintext
		// client_secret and delegates to the configurator (server-side encrypt +
		// preserve-on-blank). Reuses the configurator already built above.
		adminIssuer := service.NewAdminIssuer(configurator, authorizer)

		registrars = append(registrars,
			whoami,
			adminUser,
			adminIssuer,
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
