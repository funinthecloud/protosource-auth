// Package ed25519signer implements [signers.Signer] for the JOSE EdDSA
// algorithm using the stdlib crypto/ed25519 primitives. Keys are 32-byte
// seeds (expanded internally to 64-byte ed25519.PrivateKey) and the JWK
// form follows RFC 8037 (kty=OKP, crv=Ed25519).
package ed25519signer

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/funinthecloud/protosource-auth/signers"
)

// Algorithm is the JOSE algorithm identifier for Ed25519 signatures.
const Algorithm = "EdDSA"

// Signer is the Ed25519 implementation. The zero value is ready to use;
// no configuration is required.
type Signer struct{}

// Compile-time assertion.
var _ signers.Signer = Signer{}

// Algorithm returns "EdDSA".
func (Signer) Algorithm() string { return Algorithm }

// GenerateKeypair draws 32 random bytes for the seed and expands them into
// an ed25519 keypair. The returned privateKey is the 32-byte seed; pass it
// unchanged to Sign. The publicJWK is a UTF-8 JSON document suitable for
// publication via a JWKS endpoint.
func (Signer) GenerateKeypair() (privateKey, publicJWK []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519signer: generate key: %w", err)
	}
	seed := priv.Seed() // 32 bytes

	jwk := map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"x":   base64.RawURLEncoding.EncodeToString(pub),
	}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, nil, fmt.Errorf("ed25519signer: marshal jwk: %w", err)
	}

	return seed, jwkJSON, nil
}

// Sign produces a compact JWT whose header is {"alg":"EdDSA","typ":"JWT",
// "kid":"<kid>"} and whose payload is the caller-supplied claims bytes.
// claims must already be valid JSON — the signer does not inspect or
// re-encode it.
//
// privateKey must be a 32-byte ed25519 seed as returned by GenerateKeypair.
func (Signer) Sign(privateKey, claims []byte, kid string) (string, error) {
	if len(privateKey) != ed25519.SeedSize {
		return "", fmt.Errorf("ed25519signer: %w: private key must be %d bytes, got %d", signers.ErrInvalidKey, ed25519.SeedSize, len(privateKey))
	}
	priv := ed25519.NewKeyFromSeed(privateKey)

	header := map[string]string{
		"alg": Algorithm,
		"typ": "JWT",
		"kid": kid,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("ed25519signer: marshal header: %w", err)
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claims)
	signingInput := headerB64 + "." + claimsB64

	sig := ed25519.Sign(priv, []byte(signingInput))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

// Verify parses jwt, checks that the header's alg matches EdDSA, verifies
// the signature against publicJWK, and returns the decoded payload bytes
// on success.
func (Signer) Verify(publicJWK []byte, jwt string) ([]byte, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: expected 3 segments, got %d", signers.ErrMalformedJWT, len(parts))
	}

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header base64: %v", signers.ErrMalformedJWT, err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("%w: header json: %v", signers.ErrMalformedJWT, err)
	}
	if header.Alg != Algorithm {
		return nil, fmt.Errorf("%w: want %q, got %q", signers.ErrAlgorithmMismatch, Algorithm, header.Alg)
	}

	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload base64: %v", signers.ErrMalformedJWT, err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature base64: %v", signers.ErrMalformedJWT, err)
	}

	pubKey, err := parsePublicJWK(publicJWK)
	if err != nil {
		return nil, err
	}

	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		return nil, signers.ErrInvalidSignature
	}
	return claims, nil
}

// parsePublicJWK decodes an RFC 8037 Ed25519 JWK back into the raw
// 32-byte public key.
func parsePublicJWK(publicJWK []byte) (ed25519.PublicKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(publicJWK, &jwk); err != nil {
		return nil, fmt.Errorf("%w: jwk unmarshal: %v", signers.ErrInvalidKey, err)
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("%w: want kty=OKP crv=Ed25519, got kty=%q crv=%q", signers.ErrInvalidKey, jwk.Kty, jwk.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("%w: x base64: %v", signers.ErrInvalidKey, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key must be %d bytes, got %d", signers.ErrInvalidKey, ed25519.PublicKeySize, len(raw))
	}
	return ed25519.PublicKey(raw), nil
}
