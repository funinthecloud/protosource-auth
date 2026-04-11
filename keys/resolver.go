// Package keys provides a lazy, race-safe resolver for per-day signing
// keys. It composes a [keyproviders.KeyProvider] with a map of
// [signers.Signer]s to materialize today's (issuer, algorithm) key
// on first use, cache its plaintext in memory, and reuse the cache
// for every subsequent Sign call for the rest of the day.
//
// Design notes:
//
//   - Keys are identified by a deterministic kid of the form
//     "{issuer_id}:{YYYY-MM-DD}:{algorithm}" in UTC. Two service instances
//     racing to create today's key both derive the same id; the second
//     Apply fails with [protosource.ErrAlreadyCreated] and the loser
//     falls through to Load.
//
//   - The resolver never persists plaintext private-key bytes. Generate
//     calls signer.GenerateKeypair → provider.Encrypt → Apply. Decrypt
//     happens once per process per key (on cache miss) and the result
//     lives only in the resolver's in-memory map.
//
//   - Sign/Verify are NOT on the resolver — callers obtain a
//     [*LiveKey] and call its Sign/Verify methods. This keeps the
//     resolver a pure cache and lets callers hold a stable reference
//     for the duration of a request.
package keys

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/funinthecloud/protosource"

	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders"
	"github.com/funinthecloud/protosource-auth/signers"
)

// DefaultSigningWindow is how long a freshly generated key is the active
// signing key for its issuer and algorithm. After this window elapses the
// key transitions to verify-only status.
const DefaultSigningWindow = 24 * time.Hour

// DefaultVerifyGrace is added to signing_until to produce verify_until.
// A key continues to verify JWTs signed while it was active for
// (signing_window + verify_grace) total hours. The default (11 hours)
// covers the 10-hour token TTL plus a 1-hour clock-skew margin.
const DefaultVerifyGrace = 11 * time.Hour

// ErrNoSignerForAlgorithm is returned by the resolver when asked for a
// key whose algorithm has no registered signer.
var ErrNoSignerForAlgorithm = errors.New("keys: no signer registered for algorithm")

// LiveKey is an in-memory handle to a usable key. For signing keys it
// carries the decrypted private bytes; for verify-only keys it carries
// only the public JWK.
type LiveKey struct {
	Kid        string
	Algorithm  string
	IssuerID   string
	PrivateKey []byte // nil for verification-only handles
	PublicJWK  []byte
	signer     signers.Signer
}

// Sign produces a compact JWT with the resolved kid stamped in the
// header. Returns an error if this LiveKey has no private material
// (i.e. it came from VerificationKey).
func (k *LiveKey) Sign(claims []byte) (string, error) {
	if k.PrivateKey == nil {
		return "", errors.New("keys: LiveKey has no private material (verify-only)")
	}
	return k.signer.Sign(k.PrivateKey, claims, k.Kid)
}

// Verify validates jwt against this LiveKey's public JWK and returns
// the decoded payload.
func (k *LiveKey) Verify(jwt string) ([]byte, error) {
	return k.signer.Verify(k.PublicJWK, jwt)
}

// Resolver materializes and caches per-day signing keys for a set of
// issuers.
type Resolver struct {
	repo         KeyRepo
	provider     keyproviders.KeyProvider
	masterKeyRef string
	signers      map[string]signers.Signer

	// clock is injectable for tests; defaults to time.Now.
	clock func() time.Time
	// signingWindow and verifyGrace default to the package constants.
	signingWindow time.Duration
	verifyGrace   time.Duration

	mu    sync.Mutex
	cache map[string]*LiveKey
}

// KeyRepo is the narrow dependency the resolver needs — a subset of
// [protosource.Repo] with concrete Key types instead of the generic
// interface. Satisfied by *keyv1memory.Repository and its DynamoDB
// sibling (both embed *protosource.Repository).
type KeyRepo interface {
	Apply(ctx context.Context, cmd protosource.Commander) (int64, error)
	Load(ctx context.Context, aggregateID string) (protosource.Aggregate, error)
}

// Option mutates a Resolver at construction time.
type Option func(*Resolver)

// WithClock replaces the resolver's time source. Intended for tests.
func WithClock(clock func() time.Time) Option {
	return func(r *Resolver) { r.clock = clock }
}

// WithSigningWindow overrides how long a fresh key signs before being
// retired to verify-only status.
func WithSigningWindow(d time.Duration) Option {
	return func(r *Resolver) { r.signingWindow = d }
}

// WithVerifyGrace overrides how long past signing_until a retired key
// still verifies tokens signed while it was active.
func WithVerifyGrace(d time.Duration) Option {
	return func(r *Resolver) { r.verifyGrace = d }
}

// NewResolver constructs a Resolver bound to the given Key repository,
// KeyProvider, master-key reference, and algorithm-to-signer map.
func NewResolver(repo KeyRepo, provider keyproviders.KeyProvider, masterKeyRef string, signers map[string]signers.Signer, opts ...Option) *Resolver {
	if repo == nil {
		panic("keys.NewResolver: repo must not be nil")
	}
	if provider == nil {
		panic("keys.NewResolver: provider must not be nil")
	}
	if len(signers) == 0 {
		panic("keys.NewResolver: at least one signer must be registered")
	}
	r := &Resolver{
		repo:          repo,
		provider:      provider,
		masterKeyRef:  masterKeyRef,
		signers:       signers,
		clock:         time.Now,
		signingWindow: DefaultSigningWindow,
		verifyGrace:   DefaultVerifyGrace,
		cache:         make(map[string]*LiveKey),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// ComputeKid returns the deterministic kid for an (issuer, algorithm, day).
// Exposed so tests and hand-written tooling can compute the same id the
// resolver uses.
func ComputeKid(issuerID, algorithm string, day time.Time) string {
	return fmt.Sprintf("%s:%s:%s", issuerID, day.UTC().Format("2006-01-02"), algorithm)
}

// SigningKey returns today's active signing key for (issuerID, algorithm),
// lazily creating it if no Key aggregate exists yet. Subsequent calls
// within the same day hit the in-memory cache without touching the store
// or the KeyProvider.
func (r *Resolver) SigningKey(ctx context.Context, issuerID, algorithm string) (*LiveKey, error) {
	kid := ComputeKid(issuerID, algorithm, r.clock())

	if lk := r.lookupCache(kid); lk != nil {
		return lk, nil
	}

	// Try loading an existing key (might have been created by a peer).
	if lk, err := r.loadAndDecrypt(ctx, kid); err == nil {
		r.storeCache(lk)
		return lk, nil
	} else if !errors.Is(err, protosource.ErrAggregateNotFound) {
		return nil, err
	}

	// Not present — create it.
	signer, ok := r.signers[algorithm]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoSignerForAlgorithm, algorithm)
	}

	privateKey, publicJWK, err := signer.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("keys: generate keypair: %w", err)
	}
	wrapped, err := r.provider.Encrypt(ctx, r.masterKeyRef, privateKey)
	if err != nil {
		return nil, fmt.Errorf("keys: wrap private key: %w", err)
	}

	now := r.clock()
	effectiveAt := startOfUTCDay(now).Unix()
	signingUntil := effectiveAt + int64(r.signingWindow.Seconds())
	verifyUntil := signingUntil + int64(r.verifyGrace.Seconds())

	_, err = r.repo.Apply(ctx, &keyv1.Generate{
		Id:             kid,
		Actor:          "keys-resolver",
		IssuerId:       issuerID,
		Algorithm:      algorithm,
		PublicJwk:      publicJWK,
		WrappedPrivate: wrapped,
		KeyProvider:    r.provider.Name(),
		MasterKeyRef:   r.masterKeyRef,
		EffectiveAt:    effectiveAt,
		SigningUntil:   signingUntil,
		VerifyUntil:    verifyUntil,
	})
	if err != nil {
		// Lost the race — another instance created the same kid first.
		// Fall through to a fresh Load of the peer's version.
		if errors.Is(err, protosource.ErrAlreadyCreated) {
			lk, loadErr := r.loadAndDecrypt(ctx, kid)
			if loadErr != nil {
				return nil, fmt.Errorf("keys: load after race: %w", loadErr)
			}
			r.storeCache(lk)
			return lk, nil
		}
		return nil, fmt.Errorf("keys: apply generate: %w", err)
	}

	lk := &LiveKey{
		Kid:        kid,
		Algorithm:  algorithm,
		IssuerID:   issuerID,
		PrivateKey: privateKey,
		PublicJWK:  publicJWK,
		signer:     signer,
	}
	r.storeCache(lk)
	return lk, nil
}

// VerificationKey returns a verify-only LiveKey for an existing kid. The
// returned handle has a nil PrivateKey — attempting Sign on it errors. If
// the resolver's in-memory cache already holds a full (signing+verifying)
// entry for this kid, VerificationKey returns a stripped clone rather
// than handing out the cached entry directly, so the verify-only contract
// holds regardless of cache state.
//
// Used by the JWKS endpoint and the /authz/check path when validating
// incoming JWTs.
func (r *Resolver) VerificationKey(ctx context.Context, kid string) (*LiveKey, error) {
	if lk := r.lookupCache(kid); lk != nil {
		return &LiveKey{
			Kid:       lk.Kid,
			Algorithm: lk.Algorithm,
			IssuerID:  lk.IssuerID,
			PublicJWK: lk.PublicJWK,
			signer:    lk.signer,
		}, nil
	}
	agg, err := r.repo.Load(ctx, kid)
	if err != nil {
		return nil, err
	}
	k, ok := agg.(*keyv1.Key)
	if !ok {
		return nil, fmt.Errorf("keys: loaded aggregate is %T, want *keyv1.Key", agg)
	}
	signer, ok := r.signers[k.GetAlgorithm()]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoSignerForAlgorithm, k.GetAlgorithm())
	}
	return &LiveKey{
		Kid:       k.GetId(),
		Algorithm: k.GetAlgorithm(),
		IssuerID:  k.GetIssuerId(),
		PublicJWK: k.GetPublicJwk(),
		signer:    signer,
	}, nil
}

// ── internals ──

func (r *Resolver) lookupCache(kid string) *LiveKey {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cache[kid]
}

func (r *Resolver) storeCache(lk *LiveKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[lk.Kid] = lk
}

// loadAndDecrypt loads a Key aggregate by kid and unwraps its private
// material. Returns ErrAggregateNotFound unchanged so callers can use it
// as a signal.
func (r *Resolver) loadAndDecrypt(ctx context.Context, kid string) (*LiveKey, error) {
	agg, err := r.repo.Load(ctx, kid)
	if err != nil {
		return nil, err
	}
	k, ok := agg.(*keyv1.Key)
	if !ok {
		return nil, fmt.Errorf("keys: loaded aggregate is %T, want *keyv1.Key", agg)
	}
	signer, ok := r.signers[k.GetAlgorithm()]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNoSignerForAlgorithm, k.GetAlgorithm())
	}
	plaintext, err := r.provider.Decrypt(ctx, k.GetMasterKeyRef(), k.GetWrappedPrivate())
	if err != nil {
		return nil, fmt.Errorf("keys: unwrap private key: %w", err)
	}
	return &LiveKey{
		Kid:        k.GetId(),
		Algorithm:  k.GetAlgorithm(),
		IssuerID:   k.GetIssuerId(),
		PrivateKey: plaintext,
		PublicJWK:  k.GetPublicJwk(),
		signer:     signer,
	}, nil
}

func startOfUTCDay(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}
