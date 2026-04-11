package keys_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

// testRig stands up a full resolver wired to an in-memory Key repository,
// a local KeyProvider with a fresh master key, and an Ed25519 signer.
// clock is fixed so kid derivation is deterministic across subtests.
type testRig struct {
	resolver *keys.Resolver
	repo     keys.KeyRepo
	clock    func() time.Time
}

func newTestRig(t *testing.T) *testRig {
	t.Helper()

	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(masterKey)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	store := memorystore.New(0) // Key has no snapshots; max ~3 events per aggregate
	serializer := protobinaryserializer.NewSerializer()
	repo := keyv1.NewRepository(store, serializer)

	fixed := time.Date(2026, 4, 11, 9, 30, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }

	r := keys.NewResolver(
		repo,
		provider,
		"local-master",
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
		keys.WithClock(clock),
	)

	return &testRig{resolver: r, repo: repo, clock: clock}
}

func TestComputeKidFormat(t *testing.T) {
	day := time.Date(2026, 4, 11, 14, 0, 0, 0, time.UTC)
	kid := keys.ComputeKid("issuer-self", "EdDSA", day)
	if kid != "issuer-self:2026-04-11:EdDSA" {
		t.Errorf("ComputeKid = %q, want %q", kid, "issuer-self:2026-04-11:EdDSA")
	}
}

func TestSigningKeyLazyCreateThenCached(t *testing.T) {
	rig := newTestRig(t)
	ctx := context.Background()

	first, err := rig.resolver.SigningKey(ctx, "issuer-self", "EdDSA")
	if err != nil {
		t.Fatalf("first SigningKey: %v", err)
	}
	if first.PrivateKey == nil {
		t.Errorf("first call returned no private material")
	}
	if first.PublicJWK == nil {
		t.Errorf("first call returned no public JWK")
	}
	if first.Kid != "issuer-self:2026-04-11:EdDSA" {
		t.Errorf("Kid = %q", first.Kid)
	}

	// Second call hits the cache — must return the same *LiveKey instance
	// so the underlying private-key bytes are reused rather than re-
	// decrypted.
	second, err := rig.resolver.SigningKey(ctx, "issuer-self", "EdDSA")
	if err != nil {
		t.Fatalf("second SigningKey: %v", err)
	}
	if first != second {
		t.Errorf("second call returned a different *LiveKey; cache miss")
	}

	// Verify the Key aggregate was actually persisted.
	agg, err := rig.repo.Load(ctx, first.Kid)
	if err != nil {
		t.Fatalf("Load persisted key: %v", err)
	}
	k := agg.(*keyv1.Key)
	if k.GetState() != keyv1.State_STATE_SIGNING {
		t.Errorf("persisted Key.State = %v, want STATE_SIGNING", k.GetState())
	}
	if k.GetKeyProvider() != "local" {
		t.Errorf("persisted KeyProvider = %q, want local", k.GetKeyProvider())
	}
	if len(k.GetWrappedPrivate()) == 0 {
		t.Errorf("persisted WrappedPrivate is empty")
	}
}

func TestSigningKeySignVerifyRoundTrip(t *testing.T) {
	rig := newTestRig(t)
	ctx := context.Background()

	lk, err := rig.resolver.SigningKey(ctx, "issuer-self", "EdDSA")
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}
	claims := []byte(`{"sub":"user-1","iss":"https://auth.example.com"}`)
	jwt, err := lk.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Verification key for the same kid should validate the JWT.
	vk, err := rig.resolver.VerificationKey(ctx, lk.Kid)
	if err != nil {
		t.Fatalf("VerificationKey: %v", err)
	}
	if vk.PrivateKey != nil {
		t.Errorf("VerificationKey returned a handle with private material")
	}
	got, err := vk.Verify(jwt)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if string(got) != string(claims) {
		t.Errorf("verified claims = %q, want %q", got, claims)
	}
}

func TestSeparateIssuersGetSeparateKeys(t *testing.T) {
	rig := newTestRig(t)
	ctx := context.Background()

	a, err := rig.resolver.SigningKey(ctx, "issuer-a", "EdDSA")
	if err != nil {
		t.Fatalf("issuer-a: %v", err)
	}
	b, err := rig.resolver.SigningKey(ctx, "issuer-b", "EdDSA")
	if err != nil {
		t.Fatalf("issuer-b: %v", err)
	}
	if a.Kid == b.Kid {
		t.Errorf("two issuers got the same kid %q", a.Kid)
	}
	if string(a.PrivateKey) == string(b.PrivateKey) {
		t.Errorf("two issuers got the same private key material")
	}
	if string(a.PublicJWK) == string(b.PublicJWK) {
		t.Errorf("two issuers got the same public JWK")
	}
}

func TestSigningKeyUnknownAlgorithm(t *testing.T) {
	rig := newTestRig(t)
	_, err := rig.resolver.SigningKey(context.Background(), "issuer-self", "HS256")
	if !errors.Is(err, keys.ErrNoSignerForAlgorithm) {
		t.Errorf("SigningKey(HS256) = %v, want ErrNoSignerForAlgorithm", err)
	}
}

func TestLostRaceFallsThroughToLoad(t *testing.T) {
	// Simulate the "another instance already created today's key" case:
	// pre-apply a Generate command for the deterministic kid, then ask the
	// resolver for the same (issuer, algorithm, day). It must:
	//   1. Detect that the aggregate already exists (on Load or on
	//      Apply → ErrAlreadyCreated).
	//   2. Return a LiveKey whose public JWK matches the pre-existing one
	//      and whose private key successfully decrypts.
	ctx := context.Background()

	preSigner := ed25519signer.Signer{}
	prePriv, prePub, err := preSigner.GenerateKeypair()
	if err != nil {
		t.Fatalf("pre GenerateKeypair: %v", err)
	}

	rig2 := newSharedProviderRig(t)
	wrapped, err := rig2.sharedProvider.Encrypt(ctx, "local-master", prePriv)
	if err != nil {
		t.Fatalf("pre Encrypt: %v", err)
	}

	kid := keys.ComputeKid("issuer-self", "EdDSA", rig2.clock())
	if _, err := rig2.repo.Apply(ctx, &keyv1.Generate{
		Id:             kid,
		Actor:          "test-preseed",
		IssuerId:       "issuer-self",
		Algorithm:      "EdDSA",
		PublicJwk:      prePub,
		WrappedPrivate: wrapped,
		KeyProvider:    "local",
		MasterKeyRef:   "local-master",
		EffectiveAt:    rig2.clock().Unix(),
		SigningUntil:   rig2.clock().Unix() + 86400,
		VerifyUntil:    rig2.clock().Unix() + 86400 + 36000,
	}); err != nil {
		t.Fatalf("pre Apply Generate: %v", err)
	}

	// Now ask the resolver — it should detect the pre-existing key and
	// return it rather than generating a fresh one.
	lk, err := rig2.resolver.SigningKey(ctx, "issuer-self", "EdDSA")
	if err != nil {
		t.Fatalf("SigningKey (after pre-create): %v", err)
	}
	if string(lk.PublicJWK) != string(prePub) {
		t.Errorf("resolver returned different public JWK than pre-seeded; did not load")
	}
	if string(lk.PrivateKey) != string(prePriv) {
		t.Errorf("resolver returned different private key than pre-seeded; decryption mismatch")
	}

	// And the resolver's cache should be populated.
	lk2, _ := rig2.resolver.SigningKey(ctx, "issuer-self", "EdDSA")
	if lk != lk2 {
		t.Errorf("second call after preseed did not hit cache")
	}
}

func TestNilDepsPanic(t *testing.T) {
	_, provider := mustProvider(t)
	sig := map[string]signers.Signer{ed25519signer.Algorithm: ed25519signer.Signer{}}

	store := memorystore.New(0) // Key has no snapshots; max ~3 events per aggregate
	repo := keyv1.NewRepository(store, protobinaryserializer.NewSerializer())

	cases := []struct {
		name     string
		build    func() *keys.Resolver
		wantPanic bool
	}{
		{"nil repo", func() *keys.Resolver { return keys.NewResolver(nil, provider, "", sig) }, true},
		{"nil provider", func() *keys.Resolver { return keys.NewResolver(repo, nil, "", sig) }, true},
		{"no signers", func() *keys.Resolver { return keys.NewResolver(repo, provider, "", nil) }, true},
		{"all ok", func() *keys.Resolver { return keys.NewResolver(repo, provider, "", sig) }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				r := recover()
				panicked := r != nil
				if panicked != tc.wantPanic {
					t.Errorf("panic = %v, want %v (%v)", panicked, tc.wantPanic, r)
				}
			}()
			tc.build()
		})
	}
}

// ── helpers ──

func mustMasterKey(t *testing.T) []byte {
	t.Helper()
	k, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	return k
}

func mustProvider(t *testing.T) ([]byte, *local.Provider) {
	t.Helper()
	k := mustMasterKey(t)
	p, err := local.New(k)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return k, p
}

// sharedProviderRig is a testRig variant whose provider is exposed so the
// test body can pre-seed wrapped blobs using the same master key the
// resolver will later use to decrypt.
type sharedProviderRig struct {
	resolver       *keys.Resolver
	repo           keys.KeyRepo
	sharedProvider *local.Provider
	clock          func() time.Time
}

func newSharedProviderRig(t *testing.T) *sharedProviderRig {
	t.Helper()
	_, provider := mustProvider(t)
	store := memorystore.New(0) // Key has no snapshots; max ~3 events per aggregate
	serializer := protobinaryserializer.NewSerializer()
	repo := keyv1.NewRepository(store, serializer)
	fixed := time.Date(2026, 4, 11, 9, 30, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }
	r := keys.NewResolver(
		repo,
		provider,
		"local-master",
		map[string]signers.Signer{ed25519signer.Algorithm: ed25519signer.Signer{}},
		keys.WithClock(clock),
	)
	return &sharedProviderRig{resolver: r, repo: repo, sharedProvider: provider, clock: clock}
}

// silence unused-import complaints if a subset of tests gets disabled.
var _ = protosource.ErrAggregateNotFound
