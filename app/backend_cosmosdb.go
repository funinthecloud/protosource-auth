package app

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/data/azcosmos"

	"github.com/funinthecloud/protosource/azure/cosmosclient"
	opaquecosmos "github.com/funinthecloud/protosource/opaquedata/cosmos"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/cosmosdbstore"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
)

// NewCosmosClient constructs an Azure Cosmos DB SDK client honoring the
// CosmosEndpoint, CosmosKey, and CosmosUseDefaultCredential fields on
// cfg. Auth priority: explicit CosmosKey > DefaultAzureCredential when
// CosmosUseDefaultCredential is true. Exposed so the mgr CLI can share
// the exact same client configuration the service uses.
//
// When CosmosInsecureTLS is set the client skips TLS verification —
// required for the local Cosmos emulator which ships a self-signed
// cert. Refused at runtime for non-loopback endpoints so the flag
// cannot silently downgrade TLS against a real Cosmos account.
func NewCosmosClient(cfg *Config) (*azcosmos.Client, error) {
	if cfg.CosmosEndpoint == "" {
		return nil, errors.New("app: CosmosEndpoint must be set when Backend=cosmosdb")
	}

	clientOpts := &azcosmos.ClientOptions{}
	if cfg.CosmosInsecureTLS {
		if err := requireLoopbackEndpoint(cfg.CosmosEndpoint); err != nil {
			return nil, err
		}
		clientOpts.ClientOptions = azcore.ClientOptions{Transport: insecureCosmosTransport()}
	}

	if cfg.CosmosKey != "" {
		cred, err := azcosmos.NewKeyCredential(cfg.CosmosKey)
		if err != nil {
			return nil, fmt.Errorf("app: cosmos key credential: %w", err)
		}
		return azcosmos.NewClientWithKey(cfg.CosmosEndpoint, cred, clientOpts)
	}
	if cfg.CosmosUseDefaultCredential {
		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return nil, fmt.Errorf("app: default azure credential: %w", err)
		}
		return azcosmos.NewClient(cfg.CosmosEndpoint, cred, clientOpts)
	}
	return nil, errors.New("app: no Cosmos auth configured (set CosmosKey or CosmosUseDefaultCredential)")
}

// NewCosmosContainerClients resolves the events and aggregates
// containers from a Cosmos client, returning interface-typed clients
// ready to wire into [cosmosdbstore.New] and [opaquecosmos.New].
func NewCosmosContainerClients(client *azcosmos.Client, cfg *Config) (events, aggregates cosmosclient.ContainerClient, err error) {
	db, err := client.NewDatabase(cfg.CosmosDatabase)
	if err != nil {
		return nil, nil, fmt.Errorf("app: cosmos database handle: %w", err)
	}
	eventsC, err := db.NewContainer(cfg.EventsTable)
	if err != nil {
		return nil, nil, fmt.Errorf("app: cosmos events container handle: %w", err)
	}
	aggregatesC, err := db.NewContainer(cfg.AggregatesTable)
	if err != nil {
		return nil, nil, fmt.Errorf("app: cosmos aggregates container handle: %w", err)
	}
	return cosmosclient.Wrap(eventsC), cosmosclient.Wrap(aggregatesC), nil
}

// newCosmosDBBundle wires all five aggregate repositories against a
// single shared [cosmosdbstore.CosmosDBStore] and returns a bundle
// whose UserDirectory is GSI-backed (queries User.email via the
// generated UserClient's SelectUserByEmail against the Cosmos opaque
// store).
//
// Container creation is out of scope here — the database + containers
// named in cfg must already exist. See protosource-authmgr
// ensure-tables for an idempotent helper.
func newCosmosDBBundle(_ context.Context, cfg *Config) (*Bundle, error) {
	client, err := NewCosmosClient(cfg)
	if err != nil {
		return nil, err
	}

	eventsClient, aggregatesClient, err := NewCosmosContainerClients(client, cfg)
	if err != nil {
		return nil, err
	}

	opaqueStore := opaquecosmos.New(aggregatesClient)
	cosmosStore, err := cosmosdbstore.New(eventsClient, cosmosdbstore.WithOpaqueStore(opaqueStore))
	if err != nil {
		return nil, fmt.Errorf("app: cosmos store: %w", err)
	}

	serializer := protobinaryserializer.NewSerializer()

	userClient := userv1.NewUserClient(opaqueStore)

	return &Bundle{
		UserRepo:   userv1.NewRepository(cosmosStore, serializer),
		RoleRepo:   rolev1.NewRepository(cosmosStore, serializer),
		IssuerRepo: issuerv1.NewRepository(cosmosStore, serializer),
		KeyRepo:    keyv1.NewRepository(cosmosStore, serializer),
		TokenRepo:  tokenv1.NewRepository(cosmosStore, serializer),
		Directory:  NewOpaqueDirectory(userClient),
	}, nil
}

// insecureCosmosTransport returns an HTTP client whose TLS verification
// is disabled — intended only for the Cosmos emulator, which ships a
// self-signed cert. When http.DefaultTransport is the stdlib's
// *http.Transport (the common case), we clone it so proxy / dialer /
// keepalive defaults survive. If a caller has replaced
// http.DefaultTransport with a non-*http.Transport implementation (a
// rare but valid pattern in tests or composed binaries), we fall back
// to a fresh *http.Transport rather than panicking on a type
// assertion.
func insecureCosmosTransport() policy.Transporter {
	var t *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		t = dt.Clone()
	} else {
		t = &http.Transport{}
	}
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // emulator only; runtime gate refuses non-loopback endpoints
	return &http.Client{Transport: t}
}

// requireLoopbackEndpoint returns nil iff endpoint's host parses to a
// loopback name or IP (localhost, 127.0.0.1, ::1). Any other host
// returns an error — the runtime gate on CosmosInsecureTLS, so the
// flag cannot silently enable MITM against a real Cosmos account.
func requireLoopbackEndpoint(endpoint string) error {
	u, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("app: CosmosInsecureTLS: parse endpoint %q: %w", endpoint, err)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("app: CosmosInsecureTLS: endpoint %q has no host", endpoint)
	}
	if host == "localhost" {
		return nil
	}
	// Strip any IPv6 brackets that Hostname() already removed and check
	// for a loopback IP literal.
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("app: CosmosInsecureTLS is refused for non-loopback endpoint %q — set false for any host other than localhost / 127.0.0.1 / ::1", endpoint)
}
