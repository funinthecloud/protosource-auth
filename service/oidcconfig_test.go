package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/service"
)

func TestOIDCConfigurator_SetRoundtripAndDecrypt(t *testing.T) {
	ctx := context.Background()

	// Setup minimal issuer repo (memory) + local provider (like resolver/jwks tests).
	store := memorystore.New(0)
	serializer := protobinaryserializer.NewSerializer()
	issuerRepo := issuerv1.NewRepository(store, serializer)

	master, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(master)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	cfg := service.NewOIDCConfigurator(issuerRepo, provider, "local-master")

	// First create a KIND_EXTERNAL issuer (via raw repo Apply so we have something to configure).
	_, err = issuerRepo.Apply(ctx, &issuerv1.Register{
		Id:          "ext-1",
		Actor:       "test",
		Iss:         "https://idp.example.com",
		DisplayName: "External Test",
		Kind:        issuerv1.Kind_KIND_EXTERNAL,
	})
	if err != nil {
		t.Fatalf("seed external issuer: %v", err)
	}

	secret := []byte("super-secret-client-123")
	req := service.SetRequest{
		IssuerID:     "ext-1",
		Actor:        "test-admin",
		ClientID:     "client-abc",
		ClientSecret: secret,
		DiscoveryURL: "https://idp.example.com/.well-known/openid-configuration",
		ClaimMap: map[string]string{
			"email_at_link": "email",
		},
		JITPolicy: issuerv1.OIDCJITPolicy_JIT_AUTO_NO_ROLES,
	}
	if err := cfg.Set(ctx, req); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Load and inspect.
	agg, err := issuerRepo.Load(ctx, "ext-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	iss, ok := agg.(*issuerv1.Issuer)
	if !ok {
		t.Fatalf("loaded %T, want *Issuer", agg)
	}
	oc := iss.GetOidc()
	if oc.GetClientId() != "client-abc" {
		t.Errorf("client_id = %q", oc.GetClientId())
	}
	if len(oc.GetWrappedClientSecret()) == 0 {
		t.Error("expected wrapped_client_secret to be set")
	}
	if oc.GetClientSecretKeyProvider() != provider.Name() {
		t.Errorf("key_provider = %q", oc.GetClientSecretKeyProvider())
	}
	if oc.GetJitPolicy() != issuerv1.OIDCJITPolicy_JIT_AUTO_NO_ROLES {
		t.Errorf("jit_policy = %v", oc.GetJitPolicy())
	}

	// Decrypt must recover the exact secret.
	got, err := cfg.DecryptClientSecret(ctx, oc)
	if err != nil {
		t.Fatalf("DecryptClientSecret: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("decrypted secret mismatch: got %q want %q", got, secret)
	}

	// Clear should remove it.
	if err := cfg.Clear(ctx, "ext-1", "test-admin"); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	agg2, err := issuerRepo.Load(ctx, "ext-1")
	if err != nil {
		t.Fatalf("load after clear: %v", err)
	}
	iss2 := agg2.(*issuerv1.Issuer)
	if iss2.GetOidc().GetClientId() != "" || len(iss2.GetOidc().GetWrappedClientSecret()) != 0 {
		t.Error("expected oidc cleared")
	}
}

func TestOIDCConfigurator_PrepareForRegister(t *testing.T) {
	ctx := context.Background()
	master, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	p, err := local.New(master)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	// dummy repo (not used for prepare)
	store := memorystore.New(0)
	ser := protobinaryserializer.NewSerializer()
	repo := issuerv1.NewRepository(store, ser)
	c := service.NewOIDCConfigurator(repo, p, "local-master")

	tpl := &issuerv1.OIDCConfig{
		ClientId:     "reg-client",
		DiscoveryUrl: "https://example.com/.well-known",
	}
	secret := []byte("reg-secret")
	prep, err := c.PrepareForRegister(ctx, secret, tpl)
	if err != nil {
		t.Fatalf("PrepareForRegister: %v", err)
	}
	if prep.GetClientId() != "reg-client" {
		t.Error("template fields not preserved")
	}
	if len(prep.GetWrappedClientSecret()) == 0 {
		t.Error("secret not wrapped")
	}
	// decrypt via same provider instance
	back, _ := c.DecryptClientSecret(context.Background(), prep)
	if string(back) != "reg-secret" {
		t.Error("roundtrip via prepare failed")
	}
}

// newConfiguratorWithExternalIssuer seeds an ACTIVE KIND_EXTERNAL issuer and
// returns a configurator wired to the same repo.
func newConfiguratorWithExternalIssuer(t *testing.T, ctx context.Context, id string) (*service.OIDCConfigurator, *protosource.Repository) {
	t.Helper()
	store := memorystore.New(0)
	serializer := protobinaryserializer.NewSerializer()
	issuerRepo := issuerv1.NewRepository(store, serializer)

	master, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(master)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id:          id,
		Actor:       "test",
		Iss:         "https://idp.example.com",
		DisplayName: "External",
		Kind:        issuerv1.Kind_KIND_EXTERNAL,
	}); err != nil {
		t.Fatalf("seed external issuer: %v", err)
	}
	return service.NewOIDCConfigurator(issuerRepo, provider, "local-master"), issuerRepo
}

// An endpoint/policy-only update (no ClientSecret) must keep the existing
// wrapped secret instead of clearing it.
func TestOIDCConfigurator_PreservesSecretOnEndpointOnlyUpdate(t *testing.T) {
	ctx := context.Background()
	cfg, repo := newConfiguratorWithExternalIssuer(t, ctx, "ext-1")

	secret := []byte("the-secret")
	if err := cfg.Set(ctx, service.SetRequest{IssuerID: "ext-1", ClientID: "cid", ClientSecret: secret}); err != nil {
		t.Fatalf("initial Set: %v", err)
	}
	// Update only the discovery URL — no secret supplied.
	if err := cfg.Set(ctx, service.SetRequest{IssuerID: "ext-1", ClientID: "cid", DiscoveryURL: "https://idp.example.com/.well-known"}); err != nil {
		t.Fatalf("endpoint-only Set: %v", err)
	}

	agg, err := repo.Load(ctx, "ext-1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	oc := agg.(*issuerv1.Issuer).GetOidc()
	if len(oc.GetWrappedClientSecret()) == 0 {
		t.Fatal("wrapped secret was cleared by endpoint-only update")
	}
	got, err := cfg.DecryptClientSecret(ctx, oc)
	if err != nil {
		t.Fatalf("decrypt preserved secret: %v", err)
	}
	if string(got) != string(secret) {
		t.Errorf("preserved secret mismatch: got %q want %q", got, secret)
	}
}

// OIDC config must be rejected for non-EXTERNAL issuers.
func TestOIDCConfigurator_RejectsNonExternalIssuer(t *testing.T) {
	ctx := context.Background()
	store := memorystore.New(0)
	serializer := protobinaryserializer.NewSerializer()
	issuerRepo := issuerv1.NewRepository(store, serializer)
	master, _ := local.GenerateMasterKey()
	provider, err := local.New(master)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: "self-1", Actor: "test", Iss: "https://auth.local", DisplayName: "Self", Kind: issuerv1.Kind_KIND_SELF,
	}); err != nil {
		t.Fatalf("seed self issuer: %v", err)
	}
	cfg := service.NewOIDCConfigurator(issuerRepo, provider, "local-master")

	// It must surface as ErrIssuerNotExternal so admin handlers map it to a
	// 400 client error rather than a 500 (see applyError).
	if err := cfg.Set(ctx, service.SetRequest{IssuerID: "self-1", ClientID: "cid", ClientSecret: []byte("x")}); !errors.Is(err, service.ErrIssuerNotExternal) {
		t.Errorf("Set on KIND_SELF: err = %v, want ErrIssuerNotExternal", err)
	}
	if err := cfg.Clear(ctx, "self-1", "test"); !errors.Is(err, service.ErrIssuerNotExternal) {
		t.Errorf("Clear on KIND_SELF: err = %v, want ErrIssuerNotExternal", err)
	}
}

// Register validation (CEL) must reject oidc for KIND_SELF issuers.
func TestRegister_RejectsInitialOIDCForKindSelf(t *testing.T) {
	ctx := context.Background()
	repo := issuerv1.NewRepository(memorystore.New(0), protobinaryserializer.NewSerializer())

	if _, err := repo.Apply(ctx, &issuerv1.Register{
		Id: "self-x", Actor: "t", Iss: "https://auth.local", Kind: issuerv1.Kind_KIND_SELF,
		Oidc: &issuerv1.OIDCConfig{ClientId: "cid"},
	}); err == nil {
		t.Error("KIND_SELF register with oidc should fail validation")
	}

	if _, err := repo.Apply(ctx, &issuerv1.Register{
		Id: "self-ok", Actor: "t", Iss: "https://auth.local", Kind: issuerv1.Kind_KIND_SELF,
	}); err != nil {
		t.Errorf("KIND_SELF register without oidc: %v", err)
	}
}

// client_id min_len validation must reject an OIDCConfig with no client_id.
func TestSetOIDCConfig_RequiresClientID(t *testing.T) {
	ctx := context.Background()
	cfg, _ := newConfiguratorWithExternalIssuer(t, ctx, "ext-2")
	if err := cfg.Set(ctx, service.SetRequest{IssuerID: "ext-2", ClientSecret: []byte("x")}); err == nil {
		t.Error("SetOIDCConfig with empty client_id should fail validation")
	}
}

// recordingProvider is a fake KeyProvider that records the masterKeyRef passed
// to Decrypt so a test can prove DecryptClientSecret routes decryption through
// the ref stored on the OIDCConfig, not the configurator's current default.
// Encrypt/Decrypt use a trivial reversible "wrapped:" prefix (these tests assert
// on routing, not on real cryptography).
type recordingProvider struct {
	name        string
	decryptRefs []string
}

func (p *recordingProvider) Name() string { return p.name }

func (p *recordingProvider) Encrypt(_ context.Context, _ string, pt []byte) ([]byte, error) {
	return append([]byte("wrapped:"), pt...), nil
}

func (p *recordingProvider) Decrypt(_ context.Context, ref string, wrapped []byte) ([]byte, error) {
	p.decryptRefs = append(p.decryptRefs, ref)
	return wrapped[len("wrapped:"):], nil
}

func newRecordingConfigurator(t *testing.T, prov *recordingProvider, defaultRef string) *service.OIDCConfigurator {
	t.Helper()
	repo := issuerv1.NewRepository(memorystore.New(0), protobinaryserializer.NewSerializer())
	return service.NewOIDCConfigurator(repo, prov, defaultRef)
}

// A secret wrapped under a pinned key ref must decrypt under THAT ref, even when
// the configurator's current default ref has since rotated — otherwise Azure
// Key Vault (version-pinned decrypt) and multi-ref deployments break.
func TestOIDCConfigurator_DecryptUsesStoredMasterKeyRef(t *testing.T) {
	ctx := context.Background()
	prov := &recordingProvider{name: "local"}
	cfg := newRecordingConfigurator(t, prov, "current-ref")

	oc := &issuerv1.OIDCConfig{
		WrappedClientSecret:      []byte("wrapped:hunter2"),
		ClientSecretKeyProvider:  "local",
		ClientSecretMasterKeyRef: "pinned-v3",
	}
	got, err := cfg.DecryptClientSecret(ctx, oc)
	if err != nil {
		t.Fatalf("DecryptClientSecret: %v", err)
	}
	if string(got) != "hunter2" {
		t.Fatalf("plaintext = %q, want hunter2", got)
	}
	if len(prov.decryptRefs) != 1 || prov.decryptRefs[0] != "pinned-v3" {
		t.Fatalf("decrypt ref = %v, want [pinned-v3] (stored ref, not configurator default)", prov.decryptRefs)
	}
}

// A secret wrapped before the per-secret ref metadata existed has an empty
// stored ref; decrypt must fall back to the configurator's default ref.
func TestOIDCConfigurator_DecryptFallsBackToConfiguratorRef(t *testing.T) {
	ctx := context.Background()
	prov := &recordingProvider{name: "local"}
	cfg := newRecordingConfigurator(t, prov, "default-ref")

	oc := &issuerv1.OIDCConfig{WrappedClientSecret: []byte("wrapped:s")} // no provider, no ref
	if _, err := cfg.DecryptClientSecret(ctx, oc); err != nil {
		t.Fatalf("DecryptClientSecret: %v", err)
	}
	if len(prov.decryptRefs) != 1 || prov.decryptRefs[0] != "default-ref" {
		t.Fatalf("decrypt ref = %v, want [default-ref] fallback", prov.decryptRefs)
	}
}

// A secret wrapped by a different provider must refuse to decrypt rather than
// hand the wrong KMS a blob it cannot interpret.
func TestOIDCConfigurator_DecryptRejectsProviderMismatch(t *testing.T) {
	ctx := context.Background()
	prov := &recordingProvider{name: "local"}
	cfg := newRecordingConfigurator(t, prov, "ref")

	oc := &issuerv1.OIDCConfig{
		WrappedClientSecret:     []byte("wrapped:x"),
		ClientSecretKeyProvider: "awskms", // wrapped by a different provider
	}
	_, err := cfg.DecryptClientSecret(ctx, oc)
	if !errors.Is(err, service.ErrClientSecretProviderMismatch) {
		t.Fatalf("err = %v, want ErrClientSecretProviderMismatch", err)
	}
	if len(prov.decryptRefs) != 0 {
		t.Fatal("provider mismatch must short-circuit before calling Decrypt")
	}
}

// A nil/empty OIDCConfig returns (nil, nil) — no secret to decrypt.
func TestOIDCConfigurator_DecryptEmptyIsNil(t *testing.T) {
	prov := &recordingProvider{name: "local"}
	cfg := newRecordingConfigurator(t, prov, "ref")
	got, err := cfg.DecryptClientSecret(context.Background(), &issuerv1.OIDCConfig{})
	if err != nil || got != nil {
		t.Fatalf("DecryptClientSecret(empty) = (%q, %v), want (nil, nil)", got, err)
	}
}
