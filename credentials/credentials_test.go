package credentials_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/funinthecloud/protosource-auth/credentials"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	hash, err := credentials.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if err := credentials.Verify(hash, "correct horse battery staple"); err != nil {
		t.Errorf("Verify(correct password): %v", err)
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	hash, err := credentials.Hash("s3cret")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	err = credentials.Verify(hash, "wrong")
	if !errors.Is(err, credentials.ErrMismatch) {
		t.Errorf("Verify(wrong password) = %v, want ErrMismatch", err)
	}
}

func TestHashProducesUniqueOutputsForIdenticalInput(t *testing.T) {
	// Random salt per call: two hashes of the same password must differ.
	h1, err := credentials.Hash("same")
	if err != nil {
		t.Fatalf("Hash #1: %v", err)
	}
	h2, err := credentials.Hash("same")
	if err != nil {
		t.Fatalf("Hash #2: %v", err)
	}
	if bytes.Equal(h1, h2) {
		t.Errorf("two hashes of the same password are byte-identical; salt is not random")
	}
}

func TestHashPHCFormat(t *testing.T) {
	hash, err := credentials.Hash("x")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	s := string(hash)
	// Must be a valid argon2id PHC string.
	for _, want := range []string{"$argon2id$", "$v=19$", "m=65536", "t=3", "p=2"} {
		if !strings.Contains(s, want) {
			t.Errorf("hash %q missing expected segment %q", s, want)
		}
	}
}

func TestVerifyRejectsMalformedHash(t *testing.T) {
	cases := map[string][]byte{
		"empty":         nil,
		"not a PHC":     []byte("definitely not a hash"),
		"wrong algo":    []byte("$argon2i$v=19$m=65536,t=3,p=2$YWJjZA$ZWZnaA"),
		"bad version":   []byte("$argon2id$v=18$m=65536,t=3,p=2$YWJjZA$ZWZnaA"),
		"bad salt b64":  []byte("$argon2id$v=19$m=65536,t=3,p=2$!!!$ZWZnaA"),
		"bad params":    []byte("$argon2id$v=19$m=foo,t=bar,p=baz$YWJjZA$ZWZnaA"),
	}
	for name, hash := range cases {
		t.Run(name, func(t *testing.T) {
			err := credentials.Verify(hash, "anything")
			if !errors.Is(err, credentials.ErrMalformedHash) {
				t.Errorf("Verify(%s) = %v, want ErrMalformedHash", name, err)
			}
		})
	}
}
