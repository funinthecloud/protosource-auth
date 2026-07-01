package service

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// newSigningResolver builds a keys.Resolver backed by an in-memory key repo
// and the local (XChaCha20) provider, with an injectable clock. Shared by the
// state-cookie and oauth handler tests.
func newSigningResolver(t *testing.T, clock func() time.Time) *keys.Resolver {
	t.Helper()
	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(masterKey)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	store := memorystore.New(0)
	repo := keyv1.NewRepository(store, protobinaryserializer.NewSerializer())
	return keys.NewResolver(
		repo, provider, "local-master",
		map[string]signers.Signer{ed25519signer.Algorithm: ed25519signer.Signer{}},
		keys.WithClock(clock),
	)
}

func TestStateCookieRoundTrip(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	resolver := newSigningResolver(t, func() time.Time { return now })

	jwt, err := signState(ctx, resolver, "default", "EdDSA",
		"the-verifier", "https://app.example.com/home", "nonce-abc", "google",
		now, 10*time.Minute)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}

	claims, err := verifyState(ctx, resolver, jwt, "nonce-abc", now)
	if err != nil {
		t.Fatalf("verifyState: %v", err)
	}
	if claims.Verifier != "the-verifier" {
		t.Errorf("Verifier = %q", claims.Verifier)
	}
	if claims.RedirectURI != "https://app.example.com/home" {
		t.Errorf("RedirectURI = %q", claims.RedirectURI)
	}
	if claims.IDP != "google" {
		t.Errorf("IDP = %q", claims.IDP)
	}
	if claims.State != "nonce-abc" {
		t.Errorf("State = %q", claims.State)
	}
}

func TestStateCookieExpired(t *testing.T) {
	ctx := context.Background()
	signedAt := time.Now().UTC()
	resolver := newSigningResolver(t, func() time.Time { return signedAt })

	jwt, err := signState(ctx, resolver, "default", "EdDSA",
		"v", "https://app.example.com/", "nonce", "google",
		signedAt, 10*time.Minute)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}

	// Verify 11 minutes later — past the 10-minute TTL.
	later := signedAt.Add(11 * time.Minute)
	if _, err := verifyState(ctx, resolver, jwt, "nonce", later); err == nil {
		t.Fatal("expected expired state to be rejected")
	}
}

func TestStateCookieTampered(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	resolver := newSigningResolver(t, func() time.Time { return now })

	jwt, err := signState(ctx, resolver, "default", "EdDSA",
		"v", "https://app.example.com/", "nonce", "google", now, 10*time.Minute)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}

	// Flip the last character of the payload segment to break the signature.
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected jwt shape: %d segments", len(parts))
	}
	payload := []byte(parts[1])
	if payload[len(payload)-1] == 'A' {
		payload[len(payload)-1] = 'B'
	} else {
		payload[len(payload)-1] = 'A'
	}
	tampered := parts[0] + "." + string(payload) + "." + parts[2]

	if _, err := verifyState(ctx, resolver, tampered, "nonce", now); err == nil {
		t.Fatal("expected tampered state to be rejected")
	}
}

func TestStateCookieWrongState(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	resolver := newSigningResolver(t, func() time.Time { return now })

	jwt, err := signState(ctx, resolver, "default", "EdDSA",
		"v", "https://app.example.com/", "nonce-abc", "google", now, 10*time.Minute)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}

	// Callback presents a different state nonce than the cookie carries.
	if _, err := verifyState(ctx, resolver, jwt, "nonce-WRONG", now); err == nil {
		t.Fatal("expected state mismatch to be rejected")
	}
}

func TestStateCookieMissing(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	resolver := newSigningResolver(t, func() time.Time { return now })

	if _, err := verifyState(ctx, resolver, "", "nonce", now); err == nil {
		t.Fatal("expected empty state to be rejected")
	}
}

func TestStateCookieMissingCriticalFields(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	resolver := newSigningResolver(t, func() time.Time { return now })

	// Sign a structurally valid state cookie (crypto + sig + expiry + state-nonce all pass)
	// but leave one required claim empty. verifyState must fail closed with the sentinel.
	jwt, err := signState(ctx, resolver, "default", "EdDSA",
		"", "https://app.example.com/", "nonce", "google", now, 10*time.Minute)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}
	if _, err := verifyState(ctx, resolver, jwt, "nonce", now); err != errStateInvalid {
		t.Fatalf("expected errStateInvalid for empty Verifier, got %v", err)
	}

	jwt, err = signState(ctx, resolver, "default", "EdDSA",
		"v", "", "nonce", "google", now, 10*time.Minute)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}
	if _, err := verifyState(ctx, resolver, jwt, "nonce", now); err != errStateInvalid {
		t.Fatalf("expected errStateInvalid for empty RedirectURI, got %v", err)
	}

	jwt, err = signState(ctx, resolver, "default", "EdDSA",
		"v", "https://app.example.com/", "nonce", "", now, 10*time.Minute)
	if err != nil {
		t.Fatalf("signState: %v", err)
	}
	if _, err := verifyState(ctx, resolver, jwt, "nonce", now); err != errStateInvalid {
		t.Fatalf("expected errStateInvalid for empty IDP, got %v", err)
	}
}
