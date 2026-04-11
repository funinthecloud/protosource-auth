package ed25519signer_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

func TestAlgorithmIsEdDSA(t *testing.T) {
	if got := (ed25519signer.Signer{}).Algorithm(); got != "EdDSA" {
		t.Errorf("Algorithm = %q, want EdDSA", got)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	s := ed25519signer.Signer{}
	priv, pub, err := s.GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}

	claims := []byte(`{"sub":"user-1","iss":"https://auth.example.com","exp":9999999999}`)
	jwt, err := s.Sign(priv, claims, "kid-test")
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if strings.Count(jwt, ".") != 2 {
		t.Errorf("JWT must have 3 segments: %q", jwt)
	}

	got, err := s.Verify(pub, jwt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(claims) {
		t.Errorf("claims round-trip = %q, want %q", got, claims)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	s := ed25519signer.Signer{}
	priv, pub, _ := s.GenerateKeypair()
	jwt, _ := s.Sign(priv, []byte(`{"sub":"alice"}`), "k1")

	// Flip one character in the middle segment (payload).
	parts := strings.Split(jwt, ".")
	parts[1] = parts[1][:len(parts[1])-2] + "AA" // replace last 2 chars
	tampered := strings.Join(parts, ".")

	_, err := s.Verify(pub, tampered)
	if !errors.Is(err, signers.ErrInvalidSignature) && !errors.Is(err, signers.ErrMalformedJWT) {
		t.Errorf("Verify(tampered) = %v, want ErrInvalidSignature or ErrMalformedJWT", err)
	}
}

func TestVerifyRejectsTamperedSignature(t *testing.T) {
	s := ed25519signer.Signer{}
	priv, pub, _ := s.GenerateKeypair()
	jwt, _ := s.Sign(priv, []byte(`{}`), "k1")

	parts := strings.Split(jwt, ".")
	// Replace the signature with zeros of the same length.
	parts[2] = strings.Repeat("A", len(parts[2]))
	tampered := strings.Join(parts, ".")

	_, err := s.Verify(pub, tampered)
	if !errors.Is(err, signers.ErrInvalidSignature) {
		t.Errorf("Verify(tampered sig) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	s := ed25519signer.Signer{}
	priv1, _, _ := s.GenerateKeypair()
	_, pub2, _ := s.GenerateKeypair()

	jwt, _ := s.Sign(priv1, []byte(`{}`), "k1")
	_, err := s.Verify(pub2, jwt)
	if !errors.Is(err, signers.ErrInvalidSignature) {
		t.Errorf("Verify(wrong key) = %v, want ErrInvalidSignature", err)
	}
}

func TestVerifyRejectsWrongAlgorithmHeader(t *testing.T) {
	s := ed25519signer.Signer{}
	_, pub, _ := s.GenerateKeypair()
	// A JWT whose header claims alg=HS256 — must be rejected.
	badHeader := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // base64url of {"alg":"HS256","typ":"JWT"}
	jwt := badHeader + ".e30.AAAA"

	_, err := s.Verify(pub, jwt)
	if !errors.Is(err, signers.ErrAlgorithmMismatch) {
		t.Errorf("Verify(HS256 header) = %v, want ErrAlgorithmMismatch", err)
	}
}

func TestVerifyRejectsMalformedJWT(t *testing.T) {
	s := ed25519signer.Signer{}
	_, pub, _ := s.GenerateKeypair()

	cases := map[string]string{
		"too few segments":      "only.two",
		"too many segments":     "a.b.c.d",
		"bad base64 header":     "!!!.e30.AAAA",
		"bad base64 payload":    "eyJhbGciOiJFZERTQSJ9.!!!.AAAA",
		"bad base64 signature":  "eyJhbGciOiJFZERTQSJ9.e30.!!!",
		"empty jwt":             "",
	}
	for name, jwt := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := s.Verify(pub, jwt)
			if err == nil {
				t.Errorf("Verify(%s) = nil, want error", name)
			}
		})
	}
}

func TestSignRejectsWrongLengthPrivateKey(t *testing.T) {
	s := ed25519signer.Signer{}
	_, err := s.Sign([]byte("too-short"), []byte(`{}`), "k1")
	if !errors.Is(err, signers.ErrInvalidKey) {
		t.Errorf("Sign(short key) = %v, want ErrInvalidKey", err)
	}
}

func TestGenerateKeypairProducesDistinctKeysEachCall(t *testing.T) {
	s := ed25519signer.Signer{}
	priv1, pub1, _ := s.GenerateKeypair()
	priv2, pub2, _ := s.GenerateKeypair()

	if string(priv1) == string(priv2) {
		t.Errorf("two generated private keys are identical")
	}
	if string(pub1) == string(pub2) {
		t.Errorf("two generated public JWKs are identical")
	}
}
