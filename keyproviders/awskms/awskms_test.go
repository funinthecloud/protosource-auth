package awskms_test

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/funinthecloud/protosource-auth/keyproviders"
	"github.com/funinthecloud/protosource-auth/keyproviders/awskms"
)

// mockKMS is a fake KMS client that stores wrapped blobs in memory
// with a trivial XOR "encryption" (not secure — just for round-trip
// testing without a real KMS endpoint).
type mockKMS struct {
	failEncrypt bool
	failDecrypt bool
}

func (m *mockKMS) Encrypt(_ context.Context, in *kms.EncryptInput, _ ...func(*kms.Options)) (*kms.EncryptOutput, error) {
	if m.failEncrypt {
		return nil, errors.New("mock: encrypt failed")
	}
	// Trivial XOR with 0xAA to simulate transformation.
	blob := make([]byte, len(in.Plaintext))
	for i, b := range in.Plaintext {
		blob[i] = b ^ 0xAA
	}
	return &kms.EncryptOutput{CiphertextBlob: blob}, nil
}

func (m *mockKMS) Decrypt(_ context.Context, in *kms.DecryptInput, _ ...func(*kms.Options)) (*kms.DecryptOutput, error) {
	if m.failDecrypt {
		return nil, errors.New("mock: decrypt failed")
	}
	plain := make([]byte, len(in.CiphertextBlob))
	for i, b := range in.CiphertextBlob {
		plain[i] = b ^ 0xAA
	}
	return &kms.DecryptOutput{Plaintext: plain}, nil
}

func TestName(t *testing.T) {
	p := awskms.New(&mockKMS{})
	if got := p.Name(); got != "awskms" {
		t.Errorf("Name() = %q, want awskms", got)
	}
}

func TestRoundTrip(t *testing.T) {
	p := awskms.New(&mockKMS{})
	ctx := context.Background()
	keyRef := "arn:aws:kms:us-east-1:123456:key/test-key"
	plaintext := []byte("ed25519-private-key-material-here")

	wrapped, err := p.Encrypt(ctx, keyRef, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(wrapped) == string(plaintext) {
		t.Error("wrapped == plaintext; expected transformation")
	}

	got, err := p.Decrypt(ctx, keyRef, wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptError(t *testing.T) {
	p := awskms.New(&mockKMS{failEncrypt: true})
	_, err := p.Encrypt(context.Background(), "key-arn", []byte("data"))
	if err == nil {
		t.Fatal("expected error from Encrypt")
	}
}

func TestDecryptErrorWrapsErrDecrypt(t *testing.T) {
	p := awskms.New(&mockKMS{failDecrypt: true})
	_, err := p.Decrypt(context.Background(), "key-arn", []byte("data"))
	if err == nil {
		t.Fatal("expected error from Decrypt")
	}
	if !errors.Is(err, keyproviders.ErrDecrypt) {
		t.Errorf("Decrypt error = %v, want errors.Is(keyproviders.ErrDecrypt)", err)
	}
}
