// Package signers defines the Signer interface used by the key resolver to
// produce and verify JWTs. Each concrete signer (ed25519signer, rs256signer)
// owns the private/public key formats for one JWT algorithm and hides the
// crypto from the resolver.
//
// The resolver composes a Signer with a [keyproviders.KeyProvider]: the
// signer generates asymmetric keypairs and signs/verifies, while the key
// provider envelope-encrypts the private half under a long-lived master
// key so the event log never sees plaintext private material.
package signers

import "errors"

// Signer owns one JWT algorithm's key format, signing, verification, and
// public-key publication (JWK) logic.
//
// Implementations must be safe for concurrent use.
type Signer interface {
	// Algorithm returns the JOSE algorithm identifier for this signer,
	// e.g. "EdDSA" for Ed25519 or "RS256" for RSA-SHA256. Stored on the
	// Key aggregate so the resolver can dispatch on load.
	Algorithm() string

	// GenerateKeypair produces a fresh asymmetric keypair. privateKey is
	// an opaque byte slice that the signer interprets — the resolver
	// never reads it, only envelope-encrypts it via a KeyProvider.
	// publicJWK is the JSON serialization of the public half in RFC 7517
	// form, suitable for publication via a JWKS endpoint.
	GenerateKeypair() (privateKey, publicJWK []byte, err error)

	// Sign produces a compact-serialization JWT whose payload is the
	// given claims (raw JSON bytes — not re-encoded) and whose header
	// carries alg={Algorithm} and the provided kid.
	Sign(privateKey, claims []byte, kid string) (jwt string, err error)

	// Verify parses and validates a compact-serialization JWT against
	// publicJWK. On success it returns the raw payload bytes; on failure
	// it returns an error wrapping ErrInvalidSignature, ErrMalformedJWT,
	// or ErrAlgorithmMismatch.
	Verify(publicJWK []byte, jwt string) (claims []byte, err error)
}

// Error sentinels used by all signer implementations. Callers check these
// with errors.Is.
var (
	ErrMalformedJWT       = errors.New("signers: malformed JWT")
	ErrAlgorithmMismatch  = errors.New("signers: algorithm mismatch")
	ErrInvalidSignature   = errors.New("signers: invalid signature")
	ErrInvalidKey         = errors.New("signers: invalid key")
)
