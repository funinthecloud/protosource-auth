package service_test

import (
	"context"
	"testing"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/stores/memorystore"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"

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
	got, err := cfg.DecryptClientSecret(ctx, oc.GetWrappedClientSecret())
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
	back, _ := c.DecryptClientSecret(context.Background(), prep.GetWrappedClientSecret())
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
	got, err := cfg.DecryptClientSecret(ctx, oc.GetWrappedClientSecret())
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

	if err := cfg.Set(ctx, service.SetRequest{IssuerID: "self-1", ClientID: "cid", ClientSecret: []byte("x")}); err == nil {
		t.Error("Set on KIND_SELF issuer should be rejected")
	}
	if err := cfg.Clear(ctx, "self-1", "test"); err == nil {
		t.Error("Clear on KIND_SELF issuer should be rejected")
	}
}

// Register validation (CEL) must reject initial_oidc for KIND_SELF issuers.
func TestRegister_RejectsInitialOIDCForKindSelf(t *testing.T) {
	ctx := context.Background()
	repo := issuerv1.NewRepository(memorystore.New(0), protobinaryserializer.NewSerializer())

	if _, err := repo.Apply(ctx, &issuerv1.Register{
		Id: "self-x", Actor: "t", Iss: "https://auth.local", Kind: issuerv1.Kind_KIND_SELF,
		InitialOidc: &issuerv1.OIDCConfig{ClientId: "cid"},
	}); err == nil {
		t.Error("KIND_SELF register with initial_oidc should fail validation")
	}

	if _, err := repo.Apply(ctx, &issuerv1.Register{
		Id: "self-ok", Actor: "t", Iss: "https://auth.local", Kind: issuerv1.Kind_KIND_SELF,
	}); err != nil {
		t.Errorf("KIND_SELF register without initial_oidc: %v", err)
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