// Package azurekeyvault implements [keyproviders.KeyProvider] using
// Azure Key Vault Keys with an HSM-backed RSA KEK and RSA-OAEP-256
// direct encryption. Ed25519 signing key material is 32-64 bytes, well
// under the RSA-OAEP plaintext capacity (e.g. ~190 bytes for RSA-2048),
// so no envelope encryption is needed — same model as keyproviders/awskms.
//
// masterKeyRef is the full Key Vault key identifier URL (kid):
//
//	https://<vault>.vault.azure.net/keys/<key-name>           (latest version)
//	https://<vault>.vault.azure.net/keys/<key-name>/<version> (pinned version)
//
// Encrypt and Decrypt parse the kid, locate (or build, then cache) a
// vault-bound *azkeys.Client, and round-trip through the Key Vault REST
// API. RSA-OAEP ciphertext carries no key-version metadata, so Decrypt
// targets the version present in the kid; a kid with no version makes
// Key Vault default to "latest", which silently breaks decryption of
// previously-wrapped material the moment a new key version exists.
// Production deployments should therefore pass a version-pinned kid
// (the resolver persists the kid used to wrap each signing key on the
// Key aggregate, so per-key version pinning happens automatically as
// long as the caller seeded the resolver with a versioned ref). KEK
// rotation is a deliberate two-step operation: create a new key
// version, then re-wrap or retire any signing keys still pinned to
// the prior version before disabling it.
//
// HSM root of trust: the KEK must be created with key_type = RSA-HSM
// against a Premium-tier Key Vault. Standard-tier (software keys) is
// rejected at KEK-creation time by the tofu module — this package does
// not re-validate at runtime.
package azurekeyvault

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/funinthecloud/protosource-auth/keyproviders"
)

// KeysClient is the narrow interface the Provider needs from the Azure
// SDK's *azkeys.Client, allowing tests to supply a mock without a real
// Key Vault endpoint.
type KeysClient interface {
	Encrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.EncryptOptions) (azkeys.EncryptResponse, error)
	Decrypt(ctx context.Context, name string, version string, parameters azkeys.KeyOperationParameters, options *azkeys.DecryptOptions) (azkeys.DecryptResponse, error)
}

// ClientFactory builds a KeysClient for the given vault URL
// (e.g. "https://my-vault.vault.azure.net"). The Provider invokes the
// factory at most once per distinct vault URL — subsequent calls hit
// the in-process cache.
type ClientFactory func(vaultURL string) (KeysClient, error)

// Provider wraps and unwraps signing-key material using Azure Key
// Vault HSM-backed RSA keys with RSA-OAEP-256.
type Provider struct {
	factory ClientFactory
	clients sync.Map // vaultURL string -> KeysClient
}

// New constructs a Provider whose ClientFactory builds vault-bound
// *azkeys.Client instances using the given token credential. Use
// [azidentity.NewDefaultAzureCredential] in production (Managed
// Identity, az login, etc).
func New(cred azcore.TokenCredential) *Provider {
	if cred == nil {
		panic("azurekeyvault.New: cred must not be nil")
	}
	return NewWithFactory(func(vaultURL string) (KeysClient, error) {
		return azkeys.NewClient(vaultURL, cred, nil)
	})
}

// NewWithFactory constructs a Provider with a caller-supplied factory.
// Tests use this entry point to inject mock KeysClients without going
// through azidentity.
func NewWithFactory(factory ClientFactory) *Provider {
	if factory == nil {
		panic("azurekeyvault.NewWithFactory: factory must not be nil")
	}
	return &Provider{factory: factory}
}

// Name returns "azurekeyvault", persisted on the Key aggregate so the
// resolver knows which provider to route Decrypt through.
func (p *Provider) Name() string { return "azurekeyvault" }

// Encrypt wraps plaintext under the Key Vault key identified by
// masterKeyRef using RSA-OAEP-256.
func (p *Provider) Encrypt(ctx context.Context, masterKeyRef string, plaintext []byte) ([]byte, error) {
	vaultURL, name, version, err := parseKeyID(masterKeyRef)
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: encrypt: %w", err)
	}
	client, err := p.clientFor(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: encrypt: %w", err)
	}
	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	resp, err := client.Encrypt(ctx, name, version, azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     plaintext,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: encrypt: %w", err)
	}
	return resp.Result, nil
}

// Decrypt unwraps a blob previously produced by this provider's
// Encrypt. The masterKeyRef must pin the same key version that was
// used at Encrypt time — RSA-OAEP ciphertext carries no key-version
// metadata, so an unversioned ref will silently route to whichever
// version Key Vault currently treats as latest, and decryption will
// fail (or, worse, succeed against the wrong key) once a new version
// exists. The Resolver persists the exact kid used to wrap each
// signing key on the Key aggregate and passes it back here, so as
// long as the configured KEK ref is version-pinned at wrap time,
// per-aggregate pinning happens automatically.
func (p *Provider) Decrypt(ctx context.Context, masterKeyRef string, wrapped []byte) ([]byte, error) {
	vaultURL, name, version, err := parseKeyID(masterKeyRef)
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: %w: %w", keyproviders.ErrDecrypt, err)
	}
	client, err := p.clientFor(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: %w: %w", keyproviders.ErrDecrypt, err)
	}
	alg := azkeys.EncryptionAlgorithmRSAOAEP256
	resp, err := client.Decrypt(ctx, name, version, azkeys.KeyOperationParameters{
		Algorithm: &alg,
		Value:     wrapped,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: %w: %w", keyproviders.ErrDecrypt, err)
	}
	return resp.Result, nil
}

// clientFor returns a KeysClient bound to the given vault URL,
// building one via the factory on first request and caching it for
// subsequent calls.
func (p *Provider) clientFor(vaultURL string) (KeysClient, error) {
	if cached, ok := p.clients.Load(vaultURL); ok {
		c, ok := cached.(KeysClient)
		if !ok || c == nil {
			return nil, fmt.Errorf("cached client for %q is not a KeysClient", vaultURL)
		}
		return c, nil
	}
	client, err := p.factory(vaultURL)
	if err != nil {
		return nil, fmt.Errorf("build client for %q: %w", vaultURL, err)
	}
	if client == nil {
		return nil, fmt.Errorf("factory returned nil KeysClient for %q", vaultURL)
	}
	actual, _ := p.clients.LoadOrStore(vaultURL, client)
	c, ok := actual.(KeysClient)
	if !ok || c == nil {
		return nil, fmt.Errorf("cached client for %q is not a KeysClient", vaultURL)
	}
	return c, nil
}

// parseKeyID splits a Key Vault key identifier URL into its
// constituent vault URL, key name, and (optional) key version.
// Accepts:
//
//	https://<vault>.vault.azure.net/keys/<name>
//	https://<vault>.vault.azure.net/keys/<name>/<version>
//
// An empty version is returned for the unversioned form. The vault URL
// is normalized to scheme + host (no path / query / fragment) so it
// becomes a stable cache key.
func parseKeyID(kid string) (vaultURL, name, version string, err error) {
	if kid == "" {
		return "", "", "", errors.New("masterKeyRef is empty")
	}
	u, err := url.Parse(kid)
	if err != nil {
		return "", "", "", fmt.Errorf("parse masterKeyRef %q: %w", kid, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", "", "", fmt.Errorf("masterKeyRef %q is not an absolute URL", kid)
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "keys" || parts[1] == "" {
		return "", "", "", fmt.Errorf("masterKeyRef %q is not a Key Vault key identifier (expected /keys/<name>[/<version>])", kid)
	}
	name = parts[1]
	if len(parts) == 3 {
		if parts[2] == "" {
			return "", "", "", fmt.Errorf("masterKeyRef %q has an empty version segment", kid)
		}
		version = parts[2]
	}
	vaultURL = u.Scheme + "://" + u.Host
	return vaultURL, name, version, nil
}

var _ keyproviders.KeyProvider = (*Provider)(nil)
