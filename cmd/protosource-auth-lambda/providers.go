package main

import (
	"os"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"

	"github.com/funinthecloud/protosource-auth/app"
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
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// MasterKeyRef is a named type so wire can distinguish the KMS key
// ARN from other string values in the graph.
type MasterKeyRef string

// CORSOrigin is a named type for the allowed CORS origin.
type CORSOrigin string

func provideResolver(repo keyv1.Repo, provider keyproviders.KeyProvider, ref MasterKeyRef) *keys.Resolver {
	return keys.NewResolver(
		repo,
		provider,
		string(ref),
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
	)
}

func provideDirectory(client *userv1.UserClient) service.UserDirectory {
	return app.NewDynamoDirectory(client)
}

func provideLoginer(
	userRepo userv1.Repo,
	issuerRepo issuerv1.Repo,
	tokenRepo tokenv1.Repo,
	directory service.UserDirectory,
	resolver *keys.Resolver,
) *service.Loginer {
	return service.NewLoginer(userRepo, issuerRepo, tokenRepo, directory, resolver)
}

func provideChecker(
	tokenRepo tokenv1.Repo,
	userRepo userv1.Repo,
	roleRepo rolev1.Repo,
) *service.Checker {
	return service.NewChecker(tokenRepo, userRepo, roleRepo)
}

func provideAuthorizer(checker *service.Checker) authz.Authorizer {
	return directauthz.New(checker,
		directauthz.WithTokenSource(httpauthz.Cookie("shadow")),
	)
}

func provideService(loginer *service.Loginer, checker *service.Checker) *service.Service {
	return service.NewService(loginer, checker)
}

func providePage(loginer *service.Loginer) *loginpage.Page {
	return loginpage.New(envOrDefault("PROTOSOURCE_AUTH_ISSUER_ID", "default"), loginer)
}

func provideWhoami(tokenRepo tokenv1.Repo, userRepo userv1.Repo) *service.Whoami {
	return service.NewWhoami(tokenRepo, userRepo)
}

func provideUserHandler(repo userv1.Repo, client *userv1.UserClient, az authz.Authorizer) *userv1.Handler {
	return userv1.NewHandler(repo, client, az)
}

func provideRoleHandler(repo rolev1.Repo, client *rolev1.RoleClient, az authz.Authorizer) *rolev1.Handler {
	return rolev1.NewHandler(repo, client, az)
}

func provideIssuerHandler(repo issuerv1.Repo, client *issuerv1.IssuerClient, az authz.Authorizer) *issuerv1.Handler {
	return issuerv1.NewHandler(repo, client, az)
}

func provideKeyHandler(repo keyv1.Repo, client *keyv1.KeyClient, az authz.Authorizer) *keyv1.Handler {
	return keyv1.NewHandler(repo, client, az)
}

func provideTokenHandler(repo tokenv1.Repo, client *tokenv1.TokenClient, az authz.Authorizer) *tokenv1.Handler {
	return tokenv1.NewHandler(repo, client, az)
}

func provideRouter(
	svc *service.Service,
	page *loginpage.Page,
	whoami *service.Whoami,
	userH *userv1.Handler,
	roleH *rolev1.Handler,
	issuerH *issuerv1.Handler,
	keyH *keyv1.Handler,
	tokenH *tokenv1.Handler,
	cors CORSOrigin,
) *protosource.Router {
	r := protosource.NewRouter(svc, page, whoami, userH, roleH, issuerH, keyH, tokenH)
	if cors != "" {
		r.SetCORS(protosource.CORSConfig{
			AllowOrigins:     []string{string(cors)},
			AllowMethods:     "GET,POST,OPTIONS",
			AllowHeaders:     "Content-Type,Accept",
			AllowCredentials: true,
		})
	}
	return r
}

func provideCORSOrigin() CORSOrigin {
	return CORSOrigin(os.Getenv("PROTOSOURCE_AUTH_CORS_ORIGIN"))
}
