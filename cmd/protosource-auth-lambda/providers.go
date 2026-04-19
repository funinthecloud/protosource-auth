package main

import (
	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/app"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	"github.com/funinthecloud/protosource-auth/loginpage"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// MasterKeyRef is a named type so wire can distinguish the KMS key
// ARN from other string values in the graph.
type MasterKeyRef string

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

func provideService(loginer *service.Loginer, checker *service.Checker) *service.Service {
	return service.NewService(loginer, checker)
}

func providePage(loginer *service.Loginer) *loginpage.Page {
	return loginpage.New(envOrDefault("PROTOSOURCE_AUTH_ISSUER_ID", "default"), loginer)
}

func provideRouter(svc *service.Service, page *loginpage.Page) *protosource.Router {
	return protosource.NewRouter(svc, page)
}
