package service

import (
	"encoding/base64"
	"testing"
)

// TestS256ChallengeRFCVector pins s256Challenge to the worked example in
// RFC 7636 Appendix B, the canonical PKCE test vector.
func TestS256ChallengeRFCVector(t *testing.T) {
	const (
		verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		wantChall = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	if got := s256Challenge(verifier); got != wantChall {
		t.Fatalf("s256Challenge(%q) = %q, want %q", verifier, got, wantChall)
	}
}

// TestGenerateVerifier checks that fresh verifiers are well-formed base64url
// (decodable, no padding) and unique across calls.
func TestGenerateVerifier(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		v, err := generateVerifier()
		if err != nil {
			t.Fatalf("generateVerifier: %v", err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil {
			t.Fatalf("verifier %q is not base64url-no-pad: %v", v, err)
		}
		if len(raw) != pkceVerifierBytes {
			t.Fatalf("verifier decoded to %d bytes, want %d", len(raw), pkceVerifierBytes)
		}
		// RFC 7636 length bounds on the encoded string.
		if len(v) < 43 || len(v) > 128 {
			t.Fatalf("verifier length %d outside RFC 7636 [43,128]", len(v))
		}
		if _, dup := seen[v]; dup {
			t.Fatalf("duplicate verifier generated: %q", v)
		}
		seen[v] = struct{}{}
	}
}

// TestChallengeIsDeterministic confirms the challenge is a pure function of
// the verifier (same in, same out).
func TestChallengeIsDeterministic(t *testing.T) {
	v, err := generateVerifier()
	if err != nil {
		t.Fatalf("generateVerifier: %v", err)
	}
	if s256Challenge(v) != s256Challenge(v) {
		t.Fatal("s256Challenge is not deterministic")
	}
}
