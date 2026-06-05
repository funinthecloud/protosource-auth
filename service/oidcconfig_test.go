package service_test

import (
	"context"
	"testing"

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
	agg2, _ := issuerRepo.Load(ctx, "ext-1")
	iss2 := agg2.(*issuerv1.Issuer)
	if iss2.GetOidc().GetClientId() != "" || len(iss2.GetOidc().GetWrappedClientSecret()) != 0 {
		t.Error("expected oidc cleared")
	}
}

func TestOIDCConfigurator_PrepareForRegister(t *testing.T) {
	master, _ := local.GenerateMasterKey()
	p, _ := local.New(master)
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
	prep, err := c.PrepareForRegister(secret, tpl)
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