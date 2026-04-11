package local_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/funinthecloud/protosource-auth/keyproviders"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
)

func newTestProvider(t *testing.T) *local.Provider {
	t.Helper()
	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	p, err := local.New(masterKey)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func TestNewRejectsWrongKeyLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64} {
		_, err := local.New(make([]byte, n))
		if err == nil {
			t.Errorf("New(len=%d) should have errored", n)
		}
	}
}

func TestNameIsLocal(t *testing.T) {
	p := newTestProvider(t)
	if got := p.Name(); got != "local" {
		t.Errorf("Name = %q, want local", got)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()

	plaintext := []byte("this is a 32-byte ed25519 seed!!")
	wrapped, err := p.Encrypt(ctx, "", plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(wrapped) <= len(plaintext) {
		t.Errorf("wrapped (%d) must be larger than plaintext (%d) due to nonce + auth tag", len(wrapped), len(plaintext))
	}

	got, err := p.Decrypt(ctx, "", wrapped)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Errorf("round-trip plaintext = %q, want %q", got, plaintext)
	}
}

func TestEncryptProducesDistinctCiphertextsForIdenticalPlaintext(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	a, _ := p.Encrypt(ctx, "", []byte("same"))
	b, _ := p.Encrypt(ctx, "", []byte("same"))
	if string(a) == string(b) {
		t.Errorf("two encryptions of the same plaintext are identical; nonce is not random")
	}
}

func TestDecryptRejectsTamperedCiphertext(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	wrapped, _ := p.Encrypt(ctx, "", []byte("hello"))

	// Flip a bit in the middle of the ciphertext portion.
	wrapped[len(wrapped)/2] ^= 0x01

	_, err := p.Decrypt(ctx, "", wrapped)
	if !errors.Is(err, keyproviders.ErrDecrypt) {
		t.Errorf("Decrypt(tampered) = %v, want wrapped ErrDecrypt", err)
	}
}

func TestDecryptRejectsTooShortBlob(t *testing.T) {
	p := newTestProvider(t)
	_, err := p.Decrypt(context.Background(), "", []byte("too short"))
	if !errors.Is(err, keyproviders.ErrDecrypt) {
		t.Errorf("Decrypt(short) = %v, want ErrDecrypt", err)
	}
}

func TestDecryptRejectsWrongMasterKey(t *testing.T) {
	ctx := context.Background()
	p1 := newTestProvider(t)
	p2 := newTestProvider(t)

	wrapped, _ := p1.Encrypt(ctx, "", []byte("secret"))
	_, err := p2.Decrypt(ctx, "", wrapped)
	if !errors.Is(err, keyproviders.ErrDecrypt) {
		t.Errorf("Decrypt(wrong master) = %v, want ErrDecrypt", err)
	}
}

func TestFromEnvRejectsUnset(t *testing.T) {
	t.Setenv(local.EnvVar, "")
	_, err := local.FromEnv()
	if err == nil {
		t.Errorf("FromEnv with unset env should have errored")
	}
}

func TestFromEnvRejectsBadBase64(t *testing.T) {
	t.Setenv(local.EnvVar, "!!!not valid base64!!!")
	_, err := local.FromEnv()
	if err == nil {
		t.Errorf("FromEnv with bad base64 should have errored")
	}
}

func TestFromEnvAcceptsValidKey(t *testing.T) {
	key, _ := local.GenerateMasterKey()
	t.Setenv(local.EnvVar, base64.StdEncoding.EncodeToString(key))
	p, err := local.FromEnv()
	if err != nil {
		t.Fatalf("FromEnv: %v", err)
	}
	// Verify the provider actually works with the env-loaded key.
	wrapped, err := p.Encrypt(context.Background(), "", []byte("x"))
	if err != nil {
		t.Fatalf("Encrypt after FromEnv: %v", err)
	}
	got, err := p.Decrypt(context.Background(), "", wrapped)
	if err != nil || string(got) != "x" {
		t.Errorf("round-trip after FromEnv: got=%q err=%v", got, err)
	}
}
