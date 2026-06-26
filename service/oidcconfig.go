package service

import (
	"context"
	"errors"
	"fmt"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders"
)

// ErrIssuerNotExternal is returned when an OIDC config operation targets an
// issuer that is not KIND_EXTERNAL. It is a client-input error (the caller
// pointed SetOIDCConfig/ClearOIDCConfig at the wrong issuer kind), so callers
// map it to 400 rather than 500. See applyError.
var ErrIssuerNotExternal = errors.New("service: OIDC config requires a KIND_EXTERNAL issuer")

// OIDCConfigurator is the hand-written orchestration for setting OIDC
// client config (including client_secret) on KIND_EXTERNAL Issuers.
//
// It reuses the KeyProvider exactly as keys.Resolver does for signing
// keys: the caller supplies plaintext only here; the configurator calls
// Encrypt, populates wrapped_client_secret + client_secret_key_provider +
// client_secret_master_key_ref on the OIDCConfig, then Applies the
// SetOIDCConfig (or prepares for inclusion in Register).
//
// Plaintext secrets never appear in events, logs, or aggregate snapshots.
// Decrypt is provided for the runtime PKCE callback path (and tests).
type OIDCConfigurator struct {
	issuerRepo   AggregateRepo
	provider     keyproviders.KeyProvider
	masterKeyRef string

	actor string // audit principal for the SetOIDCConfig command
}

// NewOIDCConfigurator wires the configurator. issuerRepo and provider are
// required (panics like NewLoginer / NewResolver on nil). Behavior can be
// tuned with options (e.g. WithOIDCConfiguratorActor).
func NewOIDCConfigurator(
	issuerRepo AggregateRepo,
	provider keyproviders.KeyProvider,
	masterKeyRef string,
	opts ...OIDCConfiguratorOption,
) *OIDCConfigurator {
	if issuerRepo == nil {
		panic("service.NewOIDCConfigurator: issuerRepo must not be nil")
	}
	if provider == nil {
		panic("service.NewOIDCConfigurator: provider must not be nil")
	}
	c := &OIDCConfigurator{
		issuerRepo:   issuerRepo,
		provider:     provider,
		masterKeyRef: masterKeyRef,
		actor:        "oidc-configurator",
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// OIDCConfiguratorOption mutates at construction (e.g. WithActor).
type OIDCConfiguratorOption func(*OIDCConfigurator)

// WithOIDCConfiguratorActor overrides the actor recorded on SetOIDCConfig
// / ClearOIDCConfig commands.
func WithOIDCConfiguratorActor(actor string) OIDCConfiguratorOption {
	return func(c *OIDCConfigurator) { c.actor = actor }
}

// SetRequest is the input for setting (or rotating) OIDC config on an
// existing ACTIVE KIND_EXTERNAL issuer. ClientSecret is the plaintext
// secret (will be encrypted by the provider before the command is built).
type SetRequest struct {
	IssuerID string
	Actor    string // if empty, uses the configured default

	ClientID     string
	ClientSecret []byte // plaintext; required for most IdPs

	DiscoveryURL          string
	AuthorizationEndpoint string
	TokenEndpoint         string
	JWKSURI               string

	AllowedAudiences []string
	ClaimMap         map[string]string

	JITPolicy        issuerv1.OIDCJITPolicy
	JITDefaultRoleID string
	JITDomain        string
}

// Set encrypts the client secret (if provided) and applies a SetOIDCConfig
// command. OIDC config is only meaningful for KIND_EXTERNAL issuers, so the
// configurator loads the target issuer and rejects KIND_SELF here (the
// generated command guards only enforce state, not kind).
//
// When ClientSecret is empty, the existing wrapped secret metadata is carried
// forward so callers can update endpoints/policy without clobbering the stored
// secret. Caller-owned slices/maps are deep-copied into the command so the
// event log can't retain references to mutable caller state.
func (c *OIDCConfigurator) Set(ctx context.Context, req SetRequest) error {
	existing, err := c.loadExternalIssuer(ctx, req.IssuerID)
	if err != nil {
		return err
	}

	oc := &issuerv1.OIDCConfig{
		ClientId:              req.ClientID,
		DiscoveryUrl:          req.DiscoveryURL,
		AuthorizationEndpoint: req.AuthorizationEndpoint,
		TokenEndpoint:         req.TokenEndpoint,
		JwksUri:               req.JWKSURI,
		AllowedAudiences:      append([]string(nil), req.AllowedAudiences...),
		ClaimMap:              cloneStringMap(req.ClaimMap),
		JitPolicy:             req.JITPolicy,
		JitDefaultRoleId:      req.JITDefaultRoleID,
		JitDomain:             req.JITDomain,
	}

	if len(req.ClientSecret) > 0 {
		wrapped, err := c.provider.Encrypt(ctx, c.masterKeyRef, req.ClientSecret)
		if err != nil {
			return fmt.Errorf("service: wrap client secret: %w", err)
		}
		oc.WrappedClientSecret = wrapped
		oc.ClientSecretKeyProvider = c.provider.Name()
		oc.ClientSecretMasterKeyRef = c.masterKeyRef
	} else if prev := existing.GetOidc(); prev != nil {
		// Preserve the previously wrapped secret + provider metadata so an
		// endpoint/policy-only update doesn't silently clear credentials.
		oc.WrappedClientSecret = append([]byte(nil), prev.GetWrappedClientSecret()...)
		oc.ClientSecretKeyProvider = prev.GetClientSecretKeyProvider()
		oc.ClientSecretMasterKeyRef = prev.GetClientSecretMasterKeyRef()
	}

	actor := req.Actor
	if actor == "" {
		actor = c.actor
	}

	if _, err := c.issuerRepo.Apply(ctx, &issuerv1.SetOIDCConfig{
		Id:    req.IssuerID,
		Actor: actor,
		Oidc:  oc,
	}); err != nil {
		return fmt.Errorf("service: apply SetOIDCConfig: %w", err)
	}
	return nil
}

// loadExternalIssuer loads the issuer and verifies it is KIND_EXTERNAL.
func (c *OIDCConfigurator) loadExternalIssuer(ctx context.Context, issuerID string) (*issuerv1.Issuer, error) {
	agg, err := c.issuerRepo.Load(ctx, issuerID)
	if err != nil {
		return nil, fmt.Errorf("service: load issuer %q: %w", issuerID, err)
	}
	iss, ok := agg.(*issuerv1.Issuer)
	if !ok {
		return nil, fmt.Errorf("service: loaded %T, want *issuerv1.Issuer", agg)
	}
	if iss.GetKind() != issuerv1.Kind_KIND_EXTERNAL {
		return nil, fmt.Errorf("%w: %q is %s", ErrIssuerNotExternal, issuerID, iss.GetKind())
	}
	return iss, nil
}

// cloneStringMap returns an independent copy so the command/event can't retain
// a reference to a caller-owned map.
func cloneStringMap(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// Clear removes OIDC config from an issuer (e.g. to disable federation or
// rotate to a different IdP registration).
func (c *OIDCConfigurator) Clear(ctx context.Context, issuerID, actor string) error {
	if _, err := c.loadExternalIssuer(ctx, issuerID); err != nil {
		return err
	}
	if actor == "" {
		actor = c.actor
	}
	_, err := c.issuerRepo.Apply(ctx, &issuerv1.ClearOIDCConfig{
		Id:    issuerID,
		Actor: actor,
	})
	if err != nil {
		return fmt.Errorf("service: apply ClearOIDCConfig: %w", err)
	}
	return nil
}

// DecryptClientSecret is the runtime helper for the PKCE callback (and
// tests) to obtain the plaintext secret for token exchange with the IdP.
// It is the caller's responsibility to ensure the issuer's stored
// client_secret_key_provider matches the process provider (current
// deployments use a single provider).
func (c *OIDCConfigurator) DecryptClientSecret(ctx context.Context, wrapped []byte) ([]byte, error) {
	if len(wrapped) == 0 {
		return nil, nil
	}
	pt, err := c.provider.Decrypt(ctx, c.masterKeyRef, wrapped)
	if err != nil {
		return nil, fmt.Errorf("service: decrypt client secret: %w", err)
	}
	return pt, nil
}

// PrepareForRegister is a convenience for callers that want to create a
// KIND_EXTERNAL issuer with initial OIDC config in one Register command.
// It performs the Encrypt step and returns a populated OIDCConfig ready
// for the Register.Oidc field (or zero if no secret).
func (c *OIDCConfigurator) PrepareForRegister(ctx context.Context, plaintextSecret []byte, template *issuerv1.OIDCConfig) (*issuerv1.OIDCConfig, error) {
	if template == nil {
		template = &issuerv1.OIDCConfig{}
	}
	out := protoCloneOIDCConfig(template) // deep copy for our fields
	if len(plaintextSecret) > 0 {
		wrapped, err := c.provider.Encrypt(ctx, c.masterKeyRef, plaintextSecret)
		if err != nil {
			return nil, fmt.Errorf("service: wrap client secret for register: %w", err)
		}
		out.WrappedClientSecret = wrapped
		out.ClientSecretKeyProvider = c.provider.Name()
		out.ClientSecretMasterKeyRef = c.masterKeyRef
	}
	return out, nil
}

// protoCloneOIDCConfig does a field-by-field copy of the OIDCConfig
// message so the caller can mutate the result without affecting the
// template. (We avoid proto.Clone to keep deps minimal in this layer.)
func protoCloneOIDCConfig(in *issuerv1.OIDCConfig) *issuerv1.OIDCConfig {
	if in == nil {
		return &issuerv1.OIDCConfig{}
	}
	out := &issuerv1.OIDCConfig{
		ClientId:                 in.GetClientId(),
		WrappedClientSecret:      append([]byte(nil), in.GetWrappedClientSecret()...),
		ClientSecretKeyProvider:  in.GetClientSecretKeyProvider(),
		ClientSecretMasterKeyRef: in.GetClientSecretMasterKeyRef(),
		DiscoveryUrl:             in.GetDiscoveryUrl(),
		AuthorizationEndpoint:    in.GetAuthorizationEndpoint(),
		TokenEndpoint:            in.GetTokenEndpoint(),
		JwksUri:                  in.GetJwksUri(),
		AllowedAudiences:         append([]string(nil), in.GetAllowedAudiences()...),
		ClaimMap:                 map[string]string{},
		JitPolicy:                in.GetJitPolicy(),
		JitDefaultRoleId:         in.GetJitDefaultRoleId(),
		JitDomain:                in.GetJitDomain(),
	}
	for k, v := range in.GetClaimMap() {
		out.ClaimMap[k] = v
	}
	return out
}
