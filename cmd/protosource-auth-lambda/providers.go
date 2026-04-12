package main

import (
	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/app"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// MasterKey is a named type so wire can distinguish the raw key bytes
// from other []byte values in the graph.
type MasterKey []byte

// IssuerIss is a named type so wire can distinguish the issuer "iss"
// claim from other string values in the graph.
type IssuerIss string

func provideKeyProvider(key MasterKey) (keyproviders.KeyProvider, error) {
	return local.New([]byte(key))
}

func provideResolver(repo keyv1.Repo, provider keyproviders.KeyProvider) *keys.Resolver {
	return keys.NewResolver(
		repo,
		provider,
		"local-master",
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

func provideRouter(svc *service.Service) *protosource.Router {
	return protosource.NewRouter(svc)
}
