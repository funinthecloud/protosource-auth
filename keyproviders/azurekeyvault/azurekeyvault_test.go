package azurekeyvault_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/funinthecloud/protosource-auth/keyproviders"
	"github.com/funinthecloud/protosource-auth/keyproviders/azurekeyvault"
)

// mockKeysClient is a fake azkeys.Client that round-trips via a trivial
// XOR transformation (not secure — just exercises the wiring without a
// real Key Vault endpoint).
type mockKeysClient struct {
	failEncrypt bool
	failDecrypt bool
	// lastName/lastVersion record the last call's name + version so
	// tests can assert URL parsing routed correctly.
	lastName    string
	lastVersion string
}

func (m *mockKeysClient) Encrypt(_ context.Context, name string, version string, params azkeys.KeyOperationParameters, _ *azkeys.EncryptOptions) (azkeys.EncryptResponse, error) {
	m.lastName, m.lastVersion = name, version
	if m.failEncrypt {
		return azkeys.EncryptResponse{}, errors.New("mock: encrypt failed")
	}
	blob := make([]byte, len(params.Value))
	for i, b := range params.Value {
		blob[i] = b ^ 0xAA
	}
	return azkeys.EncryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: blob}}, nil
}

func (m *mockKeysClient) Decrypt(_ context.Context, name string, version string, params azkeys.KeyOperationParameters, _ *azkeys.DecryptOptions) (azkeys.DecryptResponse, error) {
	m.lastName, m.lastVersion = name, version
	if m.failDecrypt {
		return azkeys.DecryptResponse{}, errors.New("mock: decrypt failed")
	}
	plain := make([]byte, len(params.Value))
	for i, b := range params.Value {
		plain[i] = b ^ 0xAA
	}
	return azkeys.DecryptResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: plain}}, nil
}

// newWithMock returns a Provider plus the underlying mock so tests can
// inspect routing state. The factory builds a fresh mock per distinct
// vault URL.
func newWithMock() (*azurekeyvault.Provider, *mockKeysClient) {
	mock := &mockKeysClient{}
	return azurekeyvault.NewWithFactory(func(_ string) (azurekeyvault.KeysClient, error) {
		return mock, nil
	}), mock
}

func TestName(t *testing.T) {
	p, _ := newWithMock()
	if got := p.Name(); got != "azurekeyvault" {
		t.Errorf("Name() = %q, want azurekeyvault", got)
	}
}

func TestRoundTripWithVersion(t *testing.T) {
	p, mock := newWithMock()
	ctx := context.Background()
	keyRef := "https://my-vault.vault.azure.net/keys/auth-kek/abc123def456"
	plaintext := []byte("ed25519-private-key-material-here")

	wrapped, err := p.Encrypt(ctx, keyRef, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(wrapped) == string(plaintext) {
		t.Error("wrapped == plaintext; expected transformation")
	}
	if mock.lastName != "auth-kek" || mock.lastVersion != "abc123def456" {
		t.Errorf("Encrypt routed to name=%q version=%q, want name=auth-kek version=abc123def456", mock.lastName, mock.lastVersion)
	}

	got, err := p.Decrypt(ctx, keyRef, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
	if mock.lastVersion != "abc123def456" {
		t.Errorf("Decrypt routed to version=%q, want abc123def456", mock.lastVersion)
	}
}

func TestRoundTripWithoutVersion(t *testing.T) {
	p, mock := newWithMock()
	ctx := context.Background()
	keyRef := "https://my-vault.vault.azure.net/keys/auth-kek"
	plaintext := []byte("payload")

	if _, err := p.Encrypt(ctx, keyRef, plaintext); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if mock.lastName != "auth-kek" || mock.lastVersion != "" {
		t.Errorf("Encrypt routed to name=%q version=%q, want name=auth-kek version=\"\"", mock.lastName, mock.lastVersion)
	}
}

func TestEncryptError(t *testing.T) {
	p := azurekeyvault.NewWithFactory(func(_ string) (azurekeyvault.KeysClient, error) {
		return &mockKeysClient{failEncrypt: true}, nil
	})
	_, err := p.Encrypt(context.Background(), "https://v.vault.azure.net/keys/k", []byte("data"))
	if err == nil {
		t.Fatal("expected error from Encrypt")
	}
}

func TestDecryptErrorWrapsErrDecrypt(t *testing.T) {
	p := azurekeyvault.NewWithFactory(func(_ string) (azurekeyvault.KeysClient, error) {
		return &mockKeysClient{failDecrypt: true}, nil
	})
	_, err := p.Decrypt(context.Background(), "https://v.vault.azure.net/keys/k", []byte("data"))
	if err == nil {
		t.Fatal("expected error from Decrypt")
	}
	if !errors.Is(err, keyproviders.ErrDecrypt) {
		t.Errorf("Decrypt error = %v, want errors.Is(keyproviders.ErrDecrypt)", err)
	}
}

func TestInvalidKeyID(t *testing.T) {
	p, _ := newWithMock()
	ctx := context.Background()
	cases := []struct {
		name string
		ref  string
	}{
		{"empty", ""},
		{"not absolute", "/keys/foo"},
		{"missing keys segment", "https://v.vault.azure.net/secrets/foo"},
		{"missing key name", "https://v.vault.azure.net/keys/"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := p.Encrypt(ctx, c.ref, []byte("x")); err == nil {
				t.Error("expected error for invalid keyID")
			}
		})
	}
}

func TestClientCachingPerVault(t *testing.T) {
	builds := 0
	p := azurekeyvault.NewWithFactory(func(_ string) (azurekeyvault.KeysClient, error) {
		builds++
		return &mockKeysClient{}, nil
	})
	ctx := context.Background()
	ref1 := "https://vault-a.vault.azure.net/keys/k"
	ref2 := "https://vault-b.vault.azure.net/keys/k"

	// Two calls to the same vault → one build.
	_, _ = p.Encrypt(ctx, ref1, []byte("x"))
	_, _ = p.Encrypt(ctx, ref1, []byte("y"))
	if builds != 1 {
		t.Errorf("after 2 calls to same vault, builds=%d, want 1", builds)
	}

	// Call to a different vault → second build.
	_, _ = p.Encrypt(ctx, ref2, []byte("z"))
	if builds != 2 {
		t.Errorf("after call to second vault, builds=%d, want 2", builds)
	}
}
