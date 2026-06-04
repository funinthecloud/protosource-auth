package service

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/keys"
)

// JWKS serves GET /oauth/jwks returning an RFC 7517 JWKS document
// containing the current (and recent prior) public verification keys
// for an issuer. It is always registered (additive) so that the
// jwks_uri advertised by the OIDC discovery document has a real
// implementation.
//
// The default issuer ID comes from app config (cfg.IssuerID, typically
// "default"). Callers can override with ?issuer=... for multi-issuer
// deployments.
//
// Keys are collected by probing ComputeKid(issuer, alg, recent-day)
// + resolver.VerificationKey for the algs the resolver supports.
// Only keys whose VerifyUntil has not passed are included. The stored
// PublicJWK (key material) is augmented with kid/alg/use:"sig".
type JWKS struct {
	resolver        *keys.Resolver
	defaultIssuerID string
}

// NewJWKS constructs the JWKS registrar. resolver is required.
// defaultIssuerID defaults to "default" if empty (matching bootstrap).
func NewJWKS(resolver *keys.Resolver, defaultIssuerID string) *JWKS {
	if resolver == nil {
		panic("service.NewJWKS: resolver must not be nil")
	}
	if defaultIssuerID == "" {
		defaultIssuerID = "default"
	}
	return &JWKS{
		resolver:        resolver,
		defaultIssuerID: defaultIssuerID,
	}
}

// RegisterRoutes registers the single GET /oauth/jwks endpoint.
func (j *JWKS) RegisterRoutes(router *protosource.Router) {
	router.Handle("GET", "/oauth/jwks", j.handle)
}

func (j *JWKS) handle(ctx context.Context, req protosource.Request) protosource.Response {
	issuer := j.defaultIssuerID
	if q := req.QueryParameters["issuer"]; q != "" {
		issuer = q
	}

	algs := j.resolver.SupportedAlgorithms()
	if len(algs) == 0 {
		algs = []string{"EdDSA"}
	}

	now := time.Now().Unix()

	// Probe a sliding window of recent days per alg. 30 days is
	// intentionally generous (covers 24h signing window + 11h grace +
	// 10h token TTL + clock skew + multi-day key retention).
	seen := map[string]struct{}{}
	var jwksKeys []any

	for _, alg := range algs {
		for d := 0; d < 30; d++ {
			day := time.Now().Add(-time.Duration(d) * 24 * time.Hour)
			kid := keys.ComputeKid(issuer, alg, day)
			if _, ok := seen[kid]; ok {
				continue
			}
			seen[kid] = struct{}{}

			lk, err := j.resolver.VerificationKey(ctx, kid)
			if err != nil {
				continue
			}
			if lk.VerifyUntil != 0 && now > lk.VerifyUntil {
				continue
			}

			// The PublicJWK from Generate is the RFC 7517 key object
			// (e.g. {"kty":"OKP","crv":"Ed25519","x":"..."}) without
			// kid/alg/use. Augment for a standards-compliant JWKS.
			var jwk map[string]any
			if err := json.Unmarshal(lk.PublicJWK, &jwk); err != nil || jwk == nil {
				continue
			}
			jwk["kid"] = lk.Kid
			jwk["alg"] = lk.Algorithm
			jwk["use"] = "sig"
			jwksKeys = append(jwksKeys, jwk)
		}
	}

	body, err := json.Marshal(map[string]any{"keys": jwksKeys})
	if err != nil {
		return protosource.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       `{"error":"internal_error"}`,
			Headers:    map[string]string{"Content-Type": "application/json"},
		}
	}
	return protosource.Response{
		StatusCode: http.StatusOK,
		Body:       string(body),
		Headers:    map[string]string{"Content-Type": "application/json"},
	}
}

// Ensure JWKS satisfies RouteRegistrar.
var _ protosource.RouteRegistrar = (*JWKS)(nil)
