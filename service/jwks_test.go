package service_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

func TestJWKSReturnsRFC7517ForDefaultIssuer(t *testing.T) {
	rig := newJWKSTestRig(t)
	ctx := context.Background()

	// Force materialization of today's key for the default issuer.
	_, err := rig.resolver.SigningKey(ctx, "default", "EdDSA")
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}

	j := service.NewJWKS(rig.resolver, "default")
	router := protosource.NewRouter(j)

	got := router.Dispatch(ctx, "GET", "/oauth/jwks", protosource.Request{})
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", got.StatusCode, got.Body)
	}
	if ct := got.Headers["Content-Type"]; ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(got.Body), &doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc.Keys) == 0 {
		t.Fatalf("expected at least one key in JWKS, got 0")
	}

	k := doc.Keys[0]
	if k["kid"] == nil || k["kid"] == "" {
		t.Errorf("kid missing or empty")
	}
	if k["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA", k["alg"])
	}
	if k["use"] != "sig" {
		t.Errorf("use = %v, want sig", k["use"])
	}
	if k["kty"] != "OKP" {
		t.Errorf("kty = %v, want OKP (from ed25519signer)", k["kty"])
	}
}

func TestJWKSWithIssuerQueryParam(t *testing.T) {
	rig := newJWKSTestRig(t)
	ctx := context.Background()

	_, err := rig.resolver.SigningKey(ctx, "my-issuer", "EdDSA")
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}

	j := service.NewJWKS(rig.resolver, "default")
	router := protosource.NewRouter(j)

	// explicit issuer that has a key
	req := protosource.Request{
		QueryParameters: map[string]string{"issuer": "my-issuer"},
	}
	got := router.Dispatch(ctx, "GET", "/oauth/jwks", req)
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status %d", got.StatusCode)
	}
	var doc struct{ Keys []any `json:"keys"` }
	if err := json.Unmarshal([]byte(got.Body), &doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc.Keys) == 0 {
		t.Errorf("expected keys for explicit issuer")
	}

	// nonexistent issuer -> empty keys (valid JWKS)
	req2 := protosource.Request{
		QueryParameters: map[string]string{"issuer": "no-such-issuer"},
	}
	got2 := router.Dispatch(ctx, "GET", "/oauth/jwks", req2)
	if got2.StatusCode != http.StatusOK {
		t.Fatalf("status %d for unknown issuer", got2.StatusCode)
	}
	var doc2 struct{ Keys []any `json:"keys"` }
	if err := json.Unmarshal([]byte(got2.Body), &doc2); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc2.Keys) != 0 {
		t.Errorf("expected empty keys for unknown issuer, got %d", len(doc2.Keys))
	}
}

func TestJWKSDefaultsIssuerID(t *testing.T) {
	rig := newJWKSTestRig(t)
	ctx := context.Background()

	_, err := rig.resolver.SigningKey(ctx, "default", "EdDSA")
	if err != nil {
		t.Fatalf("SigningKey: %v", err)
	}

	// empty default -> "default"
	j := service.NewJWKS(rig.resolver, "")
	router := protosource.NewRouter(j)

	got := router.Dispatch(ctx, "GET", "/oauth/jwks", protosource.Request{})
	if got.StatusCode != http.StatusOK {
		t.Fatalf("status %d", got.StatusCode)
	}
	var doc struct{ Keys []any `json:"keys"` }
	if err := json.Unmarshal([]byte(got.Body), &doc); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(doc.Keys) == 0 {
		t.Errorf("expected keys when defaulting issuer ID")
	}
}

// newJWKSTestRig sets up a resolver + in-memory key repo + local provider
// (modeled on keys/resolver_test.go rig) so we can materialize real keys
// for JWKS handler tests without a full app.Run.
type jwksTestRig struct {
	resolver *keys.Resolver
	repo     keys.KeyRepo
}

func newJWKSTestRig(t *testing.T) *jwksTestRig {
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
	serializer := protobinaryserializer.NewSerializer()
	repo := keyv1.NewRepository(store, serializer)

	// Use real clock so that SigningKey creates a kid for "today" (real time)
	// and the JWKS handler's recent-day probe (also real time.Now) will find it
	// on d=0. (We do not assert exact kid values in these tests.)
	r := keys.NewResolver(
		repo,
		provider,
		"local-master",
		map[string]signers.Signer{
			ed25519signer.Algorithm: ed25519signer.Signer{},
		},
	)

	return &jwksTestRig{resolver: r, repo: repo}
}
