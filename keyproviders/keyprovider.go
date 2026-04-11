// Package keyproviders defines the KeyProvider interface used by the key
// resolver to envelope-encrypt signing-key private material under a
// long-lived master key. Concrete implementations live in subpackages
// ([keyproviders/local] for a file/env-var master, future [keyproviders/
// awskms], [keyproviders/gcpkms], etc.).
//
// The provider is deliberately narrow: given a master key reference and a
// plaintext blob, Encrypt produces an opaque wrapped blob and Decrypt
// inverts it. Everything else — algorithm choice, key format, rotation —
// lives elsewhere. This keeps provider implementations thin and makes
// adding new clouds a matter of translating Encrypt/Decrypt to the cloud's
// KMS primitives.
package keyproviders

import (
	"context"
	"errors"
)

// KeyProvider wraps and unwraps arbitrary plaintext blobs under a master
// key identified by an opaque masterKeyRef. The masterKeyRef format is
// provider-specific (a KMS key ARN, a GCP resource URL, a local file
// path, etc.) — the key resolver passes whatever string the operator
// configured for the issuer through unchanged.
//
// Implementations must be safe for concurrent use.
type KeyProvider interface {
	// Name returns a short identifier ("local", "awskms", "gcpkms", ...)
	// that is persisted on the Key aggregate alongside the wrapped blob
	// so a future loader knows which provider to route Decrypt through.
	Name() string

	// Encrypt wraps plaintext under the master key identified by
	// masterKeyRef. The returned wrapped blob is opaque — only Decrypt
	// reveals the original bytes.
	Encrypt(ctx context.Context, masterKeyRef string, plaintext []byte) (wrapped []byte, err error)

	// Decrypt unwraps a blob previously produced by this provider's
	// Encrypt. It is an error to pass a wrapped blob produced by a
	// different provider (e.g. an awskms blob to the local provider) —
	// the key resolver dispatches on Key.key_provider to avoid this.
	Decrypt(ctx context.Context, masterKeyRef string, wrapped []byte) (plaintext []byte, err error)
}

// ErrDecrypt indicates a generic decryption failure: wrong master key,
// tampered blob, truncated input, or algorithm incompatibility. Callers
// check with errors.Is; implementations wrap concrete cipher errors in
// this sentinel so upstream code can uniformly distinguish "you gave me a
// bad blob" from "the KMS service is down".
var ErrDecrypt = errors.New("keyproviders: decrypt failed")
