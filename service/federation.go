package service

import (
	"context"
	"errors"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
)

// FederatedIdentity is the verified identity extracted from an external
// IdP's ID token after a successful OAuth2/PKCE authorization-code exchange.
// It is the hand-off contract between the PKCE flow (which produces it from a
// signature-verified ID token + the issuer's claim_map) and the identity
// layer (which maps it to a local User, provisioning per JIT policy).
//
// Subject is the IdP's stable `sub` claim. Together with IssuerID it forms the
// link key "{issuer_id}:{subject}". Email is resolved through the issuer's
// OIDCConfig.claim_map (e.g. claim_map["email_at_link"] -> "email"). Claims is
// the full decoded ID-token claim set for policy decisions (e.g. domain rules)
// and future claim mapping; it is never persisted verbatim.
type FederatedIdentity struct {
	IssuerID string
	Subject  string
	Email    string
	Claims   map[string]any
}

// IdentityResolver maps a verified FederatedIdentity to a local User id,
// provisioning a new User (and link) per the issuer's JIT policy when no
// existing link is found. Implementations must tolerate races (two callbacks
// for the same new subject) by linking to whichever User won.
//
// This is the seam between Phase 3 (PKCE plumbing, the consumer) and Phase 2
// (User linked-identities + JIT, the implementor). The PKCE callback depends
// only on this interface, so the two can be built in parallel.
type IdentityResolver interface {
	ResolveOrProvision(ctx context.Context, fi FederatedIdentity, oidc *issuerv1.OIDCConfig) (userID string, err error)
}

// ErrJITRejected is returned by an IdentityResolver when no link exists for the
// FederatedIdentity and the issuer's JIT policy forbids auto-provisioning
// (JIT_REJECT, or DOMAIN_RULE with a non-matching email domain). The PKCE
// callback maps this to a 403 rather than a 503.
var ErrJITRejected = errors.New("service: federated identity rejected by JIT policy")

// RejectAllResolver is the safe default IdentityResolver: it provisions
// nothing and rejects every unlinked identity. It lets the PKCE flow be wired
// into the app before the real Phase 2 resolver (miy.4) lands, and is a sane
// fallback for deployments that pre-provision all users and links out of band.
type RejectAllResolver struct{}

// ResolveOrProvision always rejects: there is no link store to consult and no
// provisioning policy to apply.
func (RejectAllResolver) ResolveOrProvision(context.Context, FederatedIdentity, *issuerv1.OIDCConfig) (string, error) {
	return "", ErrJITRejected
}
