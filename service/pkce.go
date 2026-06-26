package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCE (RFC 7636) helpers for the federated-login authorization-code flow.
//
// We generate the code_verifier ourselves (rather than leaning entirely on
// golang.org/x/oauth2's GenerateVerifier) because the verifier has to be
// stashed in our signed state cookie between the /oauth/authorize and
// /oauth/callback hops, and we want a single, test-pinned implementation of
// the S256 challenge derivation. The challenge is fed to x/oauth2 via
// SetAuthURLParam and the verifier is replayed on Exchange via
// oauth2.VerifierOption, so the two stay in lockstep.

// pkceVerifierBytes is the entropy of a fresh code_verifier. 32 bytes →
// 43 base64url chars, comfortably inside RFC 7636's 43–128 character range.
const pkceVerifierBytes = 32

// generateVerifier returns a fresh PKCE code_verifier: 32 bytes of
// crypto/rand encoded as base64url-without-padding (an unreserved-character
// string per RFC 7636 §4.1).
func generateVerifier() (string, error) {
	var buf [pkceVerifierBytes]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf[:]), nil
}

// s256Challenge derives the S256 code_challenge from a code_verifier:
// base64url(SHA-256(ASCII(verifier))), no padding (RFC 7636 §4.2).
func s256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
