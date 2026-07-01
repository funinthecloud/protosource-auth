package service

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/funinthecloud/protosource"

	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
)

// ErrLinkNotFound is returned by [LinkDirectory.FindUserByLink] when no User
// is linked to the given link key. The IdentityProvisioner falls through to
// JIT policy ONLY on this sentinel (or a nil-error empty result); any other
// lookup error is propagated so a transient store/index failure fails closed
// instead of being mistaken for "no link" (which would reject a valid linked
// user under JIT_REJECT, or needlessly re-provision under AUTO/DOMAIN).
// Implementations MUST return this — not a bare nil/"" or an opaque error — to
// signal a genuine miss.
var ErrLinkNotFound = errors.New("service: linked identity not found")

// noFederatedPassword is the sentinel password hash stored on JIT-provisioned
// Users. The User aggregate's Create command requires a non-empty
// password_hash (proto min_len = 1), but federated users authenticate only via
// their external IdP and must never be able to password-login. This value is
// deliberately NOT a valid argon2id PHC string, so credentials.Verify always
// returns ErrMalformedHash — i.e. password login is impossible for these users
// while the Create invariant is still satisfied.
var noFederatedPassword = []byte("!federated-no-password!")

// LinkDirectory is the narrow lookup the IdentityProvisioner needs to turn a
// link key ("{issuer_id}:{subject}") into a local User id. It is the federated
// analogue of [UserDirectory]: where UserDirectory indexes email→user-id for
// the password login path, LinkDirectory indexes link-key→user-id for the
// federation path.
//
// Concrete implementations can be an in-memory map (see [MapLinkDirectory], for
// tests and the memorystore-backed binary) or, in production, a GSI query
// against the User aggregate store keyed by the link key. See the package-level
// docs on MapLinkDirectory for the deferred DynamoDB GSI follow-up.
type LinkDirectory interface {
	FindUserByLink(ctx context.Context, linkKey string) (userID string, err error)
}

// linkIndexWriter is an optional capability a LinkDirectory may implement to
// let the provisioner keep the index warm after a JIT provision. In-memory
// directories implement it; a GSI-backed directory that is updated out of band
// (by a projection) need not — provisioning correctness does not depend on it
// because the deterministic user id makes provisioning idempotent.
type linkIndexWriter interface {
	Add(linkKey, userID string)
}

// MapLinkDirectory is an in-memory link-key→user-id [LinkDirectory]. It mirrors
// [MapDirectory]: it is populated as identities are linked and repopulated from
// empty on every process restart.
//
// This is what the router actually wires today for ALL backends (see
// app.NewRouter): the IdentityProvisioner is backed by this in-memory directory
// even when User aggregates live in DynamoDB/Cosmos, because the persistent link
// index does not exist yet. The operational consequence after a restart is that
// the index starts cold — JIT_AUTO_NO_ROLES and JIT_DOMAIN_RULE still recognize
// returning users (their User id is a deterministic function of the link key;
// see DeterministicUserID, so Create/ErrAlreadyCreated converges on the same
// User), but JIT_REJECT issuers can only recognize links this instance has seen
// since startup and otherwise fail closed.
//
// Production deployments that store User aggregates in DynamoDB/Cosmos should
// instead provide a LinkDirectory backed by a GSI on the link key — a documented
// follow-up (protosource-auth-i1z): a projection writes one index row per
// LinkedIdentity ("{issuer_id}:{subject}" → user_id) on IdentityLinked and
// removes it on IdentityUnlinked, giving REJECT-policy recognition across
// instances and restarts.
//
// Safe for concurrent use.
type MapLinkDirectory struct {
	mu   sync.RWMutex
	data map[string]string
}

// NewMapLinkDirectory returns an empty, thread-safe MapLinkDirectory.
func NewMapLinkDirectory() *MapLinkDirectory {
	return &MapLinkDirectory{data: make(map[string]string)}
}

// Add registers a link-key→user-id mapping, overwriting any previous entry.
func (d *MapLinkDirectory) Add(linkKey, userID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.data[linkKey] = userID
}

// Remove deletes a link key's mapping. A no-op if the key is missing.
func (d *MapLinkDirectory) Remove(linkKey string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.data, linkKey)
}

// Len returns the number of entries. Intended for tests and diagnostics.
func (d *MapLinkDirectory) Len() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.data)
}

// FindUserByLink satisfies [LinkDirectory]. It returns the linked user id for
// linkKey, or ErrLinkNotFound if none is present.
func (d *MapLinkDirectory) FindUserByLink(_ context.Context, linkKey string) (string, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	id, ok := d.data[linkKey]
	if !ok {
		return "", ErrLinkNotFound
	}
	return id, nil
}

// Compile-time assertions.
var (
	_ LinkDirectory   = (*MapLinkDirectory)(nil)
	_ linkIndexWriter = (*MapLinkDirectory)(nil)
)

// IdentityProvisioner is the real [IdentityResolver]: it maps a verified
// [FederatedIdentity] to a local User id, provisioning a new User (and link)
// per the issuer's OIDC JIT policy when no link exists. It is the Phase 2
// implementor behind the seam consumed by the PKCE callback (Phase 3).
//
// Provisioning is race-safe: the User id is a deterministic function of the
// link key, so two concurrent callbacks for the same new subject derive the
// same id; the loser of the Create race recovers via protosource.ErrAlreadyCreated
// and converges on the same User. See [DeterministicUserID].
type IdentityProvisioner struct {
	userRepo AggregateRepo
	links    LinkDirectory

	clock func() time.Time
	actor string
}

// IdentityProvisionerOption mutates an IdentityProvisioner at construction.
type IdentityProvisionerOption func(*IdentityProvisioner)

// WithIdentityProvisionerClock replaces the time source (for deterministic
// linked_at / assigned_at in tests).
func WithIdentityProvisionerClock(clock func() time.Time) IdentityProvisionerOption {
	return func(p *IdentityProvisioner) { p.clock = clock }
}

// WithIdentityProvisionerActor overrides the audit principal recorded on the
// Create / LinkIdentity / AssignRole commands this provisioner emits.
func WithIdentityProvisionerActor(actor string) IdentityProvisionerOption {
	return func(p *IdentityProvisioner) { p.actor = actor }
}

// NewIdentityProvisioner wires an IdentityProvisioner. userRepo and links are
// required; passing nil panics with a descriptive message, consistent with the
// other constructors in this package.
func NewIdentityProvisioner(userRepo AggregateRepo, links LinkDirectory, opts ...IdentityProvisionerOption) *IdentityProvisioner {
	if userRepo == nil {
		panic("service.NewIdentityProvisioner: userRepo must not be nil")
	}
	if links == nil {
		panic("service.NewIdentityProvisioner: links must not be nil")
	}
	p := &IdentityProvisioner{
		userRepo: userRepo,
		links:    links,
		clock:    time.Now,
		actor:    "identity-provisioner",
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// LinkKey returns the canonical link key for a FederatedIdentity:
// "{issuer_id}:{subject}". It is the map key under User.linked_identities and
// the key the LinkDirectory indexes on.
func LinkKey(issuerID, subject string) string {
	return issuerID + ":" + subject
}

// DeterministicUserID derives a stable, URL-safe User id from a link key. It is
// a pure function of the link key (SHA-256, base64url, "fed-" prefix), so two
// concurrent callbacks for the same new subject generate the same id and
// converge on a single User via the Create/ErrAlreadyCreated race fallback —
// mirroring the deterministic-kid scheme in keys.Resolver.
func DeterministicUserID(linkKey string) string {
	sum := sha256.Sum256([]byte(linkKey))
	return "fed-" + base64.RawURLEncoding.EncodeToString(sum[:])
}

// ResolveOrProvision satisfies [IdentityResolver].
//
//  1. If a User is already linked to fi's link key, return it.
//  2. Otherwise apply the issuer's OIDC JIT policy:
//     - JIT_REJECT (zero value): return ErrJITRejected.
//     - JIT_AUTO_NO_ROLES: create a User (no usable password) + link.
//     - JIT_DOMAIN_RULE: if fi.Email's domain matches oidc.jit_domain, create a
//     User, assign oidc.jit_default_role_id (if set), and link; else reject.
//
// Provisioning tolerates the Create race (ErrAlreadyCreated) and is idempotent
// on the link and role grant, so concurrent callbacks for the same new subject
// converge on one User id.
func (p *IdentityProvisioner) ResolveOrProvision(ctx context.Context, fi FederatedIdentity, oidc *issuerv1.OIDCConfig) (string, error) {
	linkKey := LinkKey(fi.IssuerID, fi.Subject)

	switch userID, err := p.links.FindUserByLink(ctx, linkKey); {
	case err == nil && userID != "":
		return userID, nil
	case err == nil, errors.Is(err, ErrLinkNotFound):
		// No existing link — fall through to JIT policy below.
	default:
		// A real lookup failure (store/index error) must not be silently
		// treated as "not linked": fail closed so the callback surfaces a
		// 503 rather than wrongly rejecting (JIT_REJECT) or re-provisioning
		// (AUTO/DOMAIN) a user that is in fact already linked.
		return "", fmt.Errorf("service: lookup link %q: %w", linkKey, err)
	}

	switch oidc.GetJitPolicy() {
	case issuerv1.OIDCJITPolicy_JIT_AUTO_NO_ROLES:
		return p.provision(ctx, fi, linkKey, "")
	case issuerv1.OIDCJITPolicy_JIT_DOMAIN_RULE:
		// Domain-based auto-provisioning grants access purely from the email's
		// domain, so the email MUST be provably the user's. Require BOTH a
		// verified email claim and a domain match; either missing fails closed.
		if !emailVerified(fi.Claims, oidc) || !emailDomainMatches(fi.Email, oidc.GetJitDomain()) {
			return "", ErrJITRejected
		}
		return p.provision(ctx, fi, linkKey, oidc.GetJitDefaultRoleId())
	default:
		// JIT_REJECT and any unknown policy fail closed.
		return "", ErrJITRejected
	}
}

// provision creates (or reuses) the deterministic User for linkKey, optionally
// assigns roleID, and ensures the LinkedIdentity is present. Every step
// tolerates the work already being done by a racing caller.
func (p *IdentityProvisioner) provision(ctx context.Context, fi FederatedIdentity, linkKey, roleID string) (string, error) {
	now := p.clock()
	userID := DeterministicUserID(linkKey)

	email := fi.Email
	if len(email) < 3 {
		// Create requires email min_len = 3. When the IdP did not supply an
		// email (claim_map miss), synthesize a non-routable placeholder from
		// the deterministic id (RFC 2606 reserved .invalid TLD).
		email = userID + "@federated.invalid"
	}

	// 1. Create the User (tolerate a racing caller having created it first).
	if _, err := p.userRepo.Apply(ctx, &userv1.Create{
		Id:           userID,
		Actor:        p.actor,
		Email:        email,
		PasswordHash: noFederatedPassword,
	}); err != nil && !errors.Is(err, protosource.ErrAlreadyCreated) {
		return "", fmt.Errorf("service: provision user %q: %w", userID, err)
	}

	// Load the (possibly pre-existing) User so role/link applies are idempotent
	// without emitting redundant events on the race-loser path.
	user, err := p.loadUser(ctx, userID)
	if err != nil {
		return "", err
	}

	// 2. Assign the default role (JIT_DOMAIN_RULE only) if not already granted.
	if roleID != "" {
		if _, ok := user.GetRoles()[roleID]; !ok {
			if _, err := p.userRepo.Apply(ctx, &userv1.AssignRole{
				Id:    userID,
				Actor: p.actor,
				Grant: &userv1.RoleGrant{RoleId: roleID, AssignedAt: now.Unix()},
			}); err != nil {
				return "", fmt.Errorf("service: assign jit role %q to %q: %w", roleID, userID, err)
			}
		}
	}

	// 3. Ensure the LinkedIdentity is present (idempotent on the link key).
	if _, ok := user.GetLinkedIdentities()[linkKey]; !ok {
		if _, err := p.userRepo.Apply(ctx, &userv1.LinkIdentity{
			Id:    userID,
			Actor: p.actor,
			Identity: &userv1.LinkedIdentity{
				LinkKey:     linkKey,
				IssuerId:    fi.IssuerID,
				Subject:     fi.Subject,
				EmailAtLink: fi.Email,
				LinkedAt:    now.Unix(),
			},
		}); err != nil {
			return "", fmt.Errorf("service: link identity %q to %q: %w", linkKey, userID, err)
		}
	}

	// Best-effort: keep an in-memory link index warm. GSI-backed directories
	// that don't implement the writer are updated out of band.
	if w, ok := p.links.(linkIndexWriter); ok {
		w.Add(linkKey, userID)
	}

	return userID, nil
}

// loadUser loads a User aggregate by id and type-asserts it.
func (p *IdentityProvisioner) loadUser(ctx context.Context, userID string) (*userv1.User, error) {
	agg, err := p.userRepo.Load(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service: load user %q: %w", userID, err)
	}
	user, ok := agg.(*userv1.User)
	if !ok {
		return nil, fmt.Errorf("service: loaded %T, want *userv1.User", agg)
	}
	return user, nil
}

// emailVerified reports whether the ID-token claims assert a verified email,
// using the issuer's claim_map: claim_map["email_verified"] names the IdP
// claim carrying the verification flag (default: the standard "email_verified"
// claim). The OIDC spec types email_verified as a JSON boolean, but some
// providers encode it as the string "true"; both are accepted. A missing
// claim, a false value, or any other shape is treated as unverified — fail
// closed. Only JIT_DOMAIN_RULE consults this, because it is the one policy that
// grants access from the email domain rather than from the verified subject
// link alone.
func emailVerified(claims map[string]any, oc *issuerv1.OIDCConfig) bool {
	name := oc.GetClaimMap()["email_verified"]
	if name == "" {
		name = "email_verified"
	}
	switch v := claims[name].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return false
	}
}

// emailDomainMatches reports whether email's domain satisfies a jit_domain
// rule. Per the proto contract, a leading-dot jit_domain (".corp.example.com")
// is a suffix rule matching that domain and all its subdomains; a bare
// jit_domain ("example.com") is an exact match. Comparison is
// case-insensitive. An empty email, missing "@", or empty jit_domain never
// matches.
func emailDomainMatches(email, jitDomain string) bool {
	if jitDomain == "" {
		return false
	}
	at := strings.LastIndexByte(email, '@')
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(email[at+1:])
	jitDomain = strings.ToLower(jitDomain)

	if strings.HasPrefix(jitDomain, ".") {
		bare := jitDomain[1:]
		return domain == bare || strings.HasSuffix(domain, jitDomain)
	}
	return domain == jitDomain
}

// Compile-time assertion that the provisioner satisfies the committed seam.
var _ IdentityResolver = (*IdentityProvisioner)(nil)
