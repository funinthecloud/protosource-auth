// Package local implements [keyproviders.KeyProvider] backed by a single
// in-process master key using XChaCha20-Poly1305 authenticated encryption
// (RFC 8439 with extended nonces for safe random nonce generation).
//
// Intended for local development, unit tests, and single-node deployments
// that do not need a hosted KMS. Production deployments should use a
// cloud KMS-backed provider (awskms, gcpkms, etc.) so the master key
// never lives in application memory.
package local

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/funinthecloud/protosource-auth/keyproviders"
)

// EnvVar is the environment variable that [FromEnv] reads. The value must
// be a base64-encoded 32-byte master key.
const EnvVar = "PROTOSOURCE_AUTH_LOCAL_MASTER_KEY"

// Provider is the local XChaCha20-Poly1305 KeyProvider.
type Provider struct {
	masterKey []byte
}

// New returns a Provider using the given 32-byte master key. Any other
// length is an error.
func New(masterKey []byte) (*Provider, error) {
	if len(masterKey) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("local: master key must be %d bytes, got %d", chacha20poly1305.KeySize, len(masterKey))
	}
	// Copy so the caller cannot mutate our key out from under us.
	k := make([]byte, len(masterKey))
	copy(k, masterKey)
	return &Provider{masterKey: k}, nil
}

// FromEnv returns a Provider whose master key is read from the
// PROTOSOURCE_AUTH_LOCAL_MASTER_KEY environment variable, base64 decoded.
// Returns an error if the variable is unset or the decoded value is the
// wrong length.
func FromEnv() (*Provider, error) {
	raw := os.Getenv(EnvVar)
	if raw == "" {
		return nil, fmt.Errorf("local: %s not set", EnvVar)
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("local: invalid %s: %w", EnvVar, err)
	}
	return New(key)
}

// GenerateMasterKey returns 32 random bytes suitable for use as a master
// key. Intended for bootstrap scripts and tests.
func GenerateMasterKey() ([]byte, error) {
	k := make([]byte, chacha20poly1305.KeySize)
	if _, err := rand.Read(k); err != nil {
		return nil, fmt.Errorf("local: generate master key: %w", err)
	}
	return k, nil
}

// Name returns "local".
func (p *Provider) Name() string { return "local" }

// Encrypt wraps plaintext with XChaCha20-Poly1305 under the master key.
// masterKeyRef is ignored — the local provider has exactly one key, set
// at construction.
func (p *Provider) Encrypt(_ context.Context, _ string, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("local: init cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("local: read nonce: %w", err)
	}
	// Output layout: [nonce || ciphertext || tag].
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt unwraps a blob previously produced by Encrypt. Any failure —
// wrong master key, truncated input, tampered bytes — is wrapped in
// [keyproviders.ErrDecrypt] so callers can distinguish bad-blob errors
// from other failures.
func (p *Provider) Decrypt(_ context.Context, _ string, wrapped []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(p.masterKey)
	if err != nil {
		return nil, fmt.Errorf("local: init cipher: %w", err)
	}
	if len(wrapped) < aead.NonceSize() {
		return nil, fmt.Errorf("%w: wrapped blob shorter than nonce", keyproviders.ErrDecrypt)
	}
	nonce, ciphertext := wrapped[:aead.NonceSize()], wrapped[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", keyproviders.ErrDecrypt, err)
	}
	return plaintext, nil
}

// Compile-time assertion that Provider satisfies [keyproviders.KeyProvider].
var _ keyproviders.KeyProvider = (*Provider)(nil)
