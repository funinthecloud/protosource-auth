package service_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	"github.com/funinthecloud/protosource-auth/credentials"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/service"
)

// fixedClock returns a deterministic time source for linked_at / assigned_at.
func fixedClock() func() time.Time {
	t := time.Date(2026, 6, 26, 12, 0, 0, 0, time.UTC)
	return func() time.Time { return t }
}

// newUserRepo builds a fresh memorystore-backed User repository.
func newUserRepo() service.AggregateRepo {
	store := memorystore.New(userv1.SnapshotEveryNEvents)
	return userv1.NewRepository(store, protobinaryserializer.NewSerializer())
}

// loadUser is a test helper to fetch a User aggregate by id.
func loadUser(t *testing.T, repo service.AggregateRepo, id string) *userv1.User {
	t.Helper()
	agg, err := repo.Load(context.Background(), id)
	if err != nil {
		t.Fatalf("load user %q: %v", id, err)
	}
	u, ok := agg.(*userv1.User)
	if !ok {
		t.Fatalf("loaded %T, want *userv1.User", agg)
	}
	return u
}

func TestResolveOrProvision_ExistingLinkReturnsUser(t *testing.T) {
	repo := newUserRepo()
	links := service.NewMapLinkDirectory()
	links.Add(service.LinkKey("iss-google", "sub-123"), "existing-user-id")

	p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

	got, err := p.ResolveOrProvision(context.Background(), service.FederatedIdentity{
		IssuerID: "iss-google",
		Subject:  "sub-123",
		Email:    "alice@example.com",
	}, &issuerv1.OIDCConfig{JitPolicy: issuerv1.OIDCJITPolicy_JIT_REJECT})
	if err != nil {
		t.Fatalf("ResolveOrProvision: %v", err)
	}
	if got != "existing-user-id" {
		t.Fatalf("got %q, want existing-user-id", got)
	}
	// No User should have been provisioned.
	if _, err := repo.Load(context.Background(), service.DeterministicUserID(service.LinkKey("iss-google", "sub-123"))); err == nil {
		// Loading a never-created aggregate returns ErrAggregateNotFound.
		if u := loadUser(t, repo, service.DeterministicUserID(service.LinkKey("iss-google", "sub-123"))); u.GetState() != userv1.State_STATE_UNSPECIFIED {
			t.Fatalf("expected no provisioned user, got state %v", u.GetState())
		}
	}
}

func TestResolveOrProvision_RejectPolicy(t *testing.T) {
	repo := newUserRepo()
	links := service.NewMapLinkDirectory()
	p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

	cases := []struct {
		name string
		oidc *issuerv1.OIDCConfig
	}{
		{"explicit reject", &issuerv1.OIDCConfig{JitPolicy: issuerv1.OIDCJITPolicy_JIT_REJECT}},
		{"nil config (zero value)", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := p.ResolveOrProvision(context.Background(), service.FederatedIdentity{
				IssuerID: "iss-x",
				Subject:  "sub-x",
				Email:    "bob@example.com",
			}, tc.oidc)
			if !errors.Is(err, service.ErrJITRejected) {
				t.Fatalf("got %v, want ErrJITRejected", err)
			}
			if links.Len() != 0 {
				t.Fatalf("link directory should stay empty, got %d", links.Len())
			}
		})
	}
}

func TestResolveOrProvision_AutoNoRoles(t *testing.T) {
	repo := newUserRepo()
	links := service.NewMapLinkDirectory()
	p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

	fi := service.FederatedIdentity{IssuerID: "iss-google", Subject: "sub-42", Email: "carol@example.com"}
	linkKey := service.LinkKey(fi.IssuerID, fi.Subject)

	got, err := p.ResolveOrProvision(context.Background(), fi, &issuerv1.OIDCConfig{
		JitPolicy: issuerv1.OIDCJITPolicy_JIT_AUTO_NO_ROLES,
	})
	if err != nil {
		t.Fatalf("ResolveOrProvision: %v", err)
	}
	if want := service.DeterministicUserID(linkKey); got != want {
		t.Fatalf("got id %q, want deterministic %q", got, want)
	}

	u := loadUser(t, repo, got)
	if u.GetState() != userv1.State_STATE_ACTIVE {
		t.Fatalf("user state = %v, want ACTIVE", u.GetState())
	}
	if u.GetEmail() != fi.Email {
		t.Fatalf("user email = %q, want %q", u.GetEmail(), fi.Email)
	}
	if len(u.GetRoles()) != 0 {
		t.Fatalf("AUTO_NO_ROLES granted roles: %v", u.GetRoles())
	}
	li, ok := u.GetLinkedIdentities()[linkKey]
	if !ok {
		t.Fatalf("link %q not present: %v", linkKey, u.GetLinkedIdentities())
	}
	if li.GetIssuerId() != fi.IssuerID || li.GetSubject() != fi.Subject || li.GetEmailAtLink() != fi.Email {
		t.Fatalf("linked identity mismatch: %+v", li)
	}
	// Federated user must not be able to password-login.
	if err := credentials.Verify(u.GetPasswordHash(), "anything"); err == nil {
		t.Fatal("expected federated user password to be unverifiable")
	}
	// Index kept warm.
	if id, err := links.FindUserByLink(context.Background(), linkKey); err != nil || id != got {
		t.Fatalf("link directory not updated: id=%q err=%v", id, err)
	}
}

func TestResolveOrProvision_DomainRule(t *testing.T) {
	cases := []struct {
		name       string
		jitDomain  string
		email      string
		wantErr    bool
		wantRoleID string
	}{
		{"exact match grants role", "example.com", "dave@example.com", false, "role-eng"},
		{"exact non-match rejects", "example.com", "dave@evil.com", true, ""},
		{"subdomain not allowed by bare domain", "example.com", "dave@eng.example.com", true, ""},
		{"leading-dot suffix matches subdomain", ".corp.example.com", "x@us.corp.example.com", false, "role-eng"},
		{"leading-dot matches bare domain", ".corp.example.com", "x@corp.example.com", false, "role-eng"},
		{"leading-dot non-match rejects", ".corp.example.com", "x@example.com", true, ""},
		{"case insensitive", "Example.com", "dave@EXAMPLE.COM", false, "role-eng"},
		{"empty email rejects", "example.com", "", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newUserRepo()
			links := service.NewMapLinkDirectory()
			p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

			fi := service.FederatedIdentity{IssuerID: "iss-corp", Subject: "sub-" + tc.name, Email: tc.email}
			got, err := p.ResolveOrProvision(context.Background(), fi, &issuerv1.OIDCConfig{
				JitPolicy:        issuerv1.OIDCJITPolicy_JIT_DOMAIN_RULE,
				JitDomain:        tc.jitDomain,
				JitDefaultRoleId: "role-eng",
			})
			if tc.wantErr {
				if !errors.Is(err, service.ErrJITRejected) {
					t.Fatalf("got %v, want ErrJITRejected", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveOrProvision: %v", err)
			}
			u := loadUser(t, repo, got)
			if _, ok := u.GetRoles()[tc.wantRoleID]; !ok {
				t.Fatalf("role %q not granted: %v", tc.wantRoleID, u.GetRoles())
			}
			if _, ok := u.GetLinkedIdentities()[service.LinkKey(fi.IssuerID, fi.Subject)]; !ok {
				t.Fatalf("link not present: %v", u.GetLinkedIdentities())
			}
		})
	}
}

func TestResolveOrProvision_DomainRuleNoDefaultRole(t *testing.T) {
	repo := newUserRepo()
	links := service.NewMapLinkDirectory()
	p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

	fi := service.FederatedIdentity{IssuerID: "iss-corp", Subject: "sub-norole", Email: "e@example.com"}
	got, err := p.ResolveOrProvision(context.Background(), fi, &issuerv1.OIDCConfig{
		JitPolicy: issuerv1.OIDCJITPolicy_JIT_DOMAIN_RULE,
		JitDomain: "example.com",
		// JitDefaultRoleId intentionally empty.
	})
	if err != nil {
		t.Fatalf("ResolveOrProvision: %v", err)
	}
	u := loadUser(t, repo, got)
	if len(u.GetRoles()) != 0 {
		t.Fatalf("expected no roles when jit_default_role_id is empty, got %v", u.GetRoles())
	}
}

func TestResolveOrProvision_MissingEmailSynthesizesPlaceholder(t *testing.T) {
	repo := newUserRepo()
	links := service.NewMapLinkDirectory()
	p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

	fi := service.FederatedIdentity{IssuerID: "iss-google", Subject: "sub-noemail"}
	got, err := p.ResolveOrProvision(context.Background(), fi, &issuerv1.OIDCConfig{
		JitPolicy: issuerv1.OIDCJITPolicy_JIT_AUTO_NO_ROLES,
	})
	if err != nil {
		t.Fatalf("ResolveOrProvision: %v", err)
	}
	u := loadUser(t, repo, got)
	if len(u.GetEmail()) < 3 {
		t.Fatalf("expected synthesized placeholder email, got %q", u.GetEmail())
	}
	// email_at_link reflects what the IdP gave us (nothing), not the placeholder.
	li := u.GetLinkedIdentities()[service.LinkKey(fi.IssuerID, fi.Subject)]
	if li.GetEmailAtLink() != "" {
		t.Fatalf("email_at_link = %q, want empty", li.GetEmailAtLink())
	}
}

// serializedRepo wraps an AggregateRepo so every Apply/Load is mutually
// exclusive. memorystore does not enforce optimistic concurrency, so without
// this a concurrent Create race would silently append duplicate Created events
// instead of surfacing ErrAlreadyCreated. Serializing models the create-once
// guarantee a real (DynamoDB/Cosmos) store provides, exercising the
// provisioner's ErrAlreadyCreated fallback and idempotent link/role path.
type serializedRepo struct {
	mu    sync.Mutex
	inner service.AggregateRepo
}

func (r *serializedRepo) Apply(ctx context.Context, cmd protosource.Commander) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.Apply(ctx, cmd)
}

func (r *serializedRepo) Load(ctx context.Context, id string) (protosource.Aggregate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inner.Load(ctx, id)
}

func TestResolveOrProvision_RaceConvergesToOneUser(t *testing.T) {
	repo := &serializedRepo{inner: newUserRepo()}
	links := service.NewMapLinkDirectory()
	p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

	fi := service.FederatedIdentity{IssuerID: "iss-google", Subject: "sub-race", Email: "race@example.com"}
	linkKey := service.LinkKey(fi.IssuerID, fi.Subject)

	const n = 16
	ids := make([]string, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ids[i], errs[i] = p.ResolveOrProvision(context.Background(), fi, &issuerv1.OIDCConfig{
				JitPolicy: issuerv1.OIDCJITPolicy_JIT_AUTO_NO_ROLES,
			})
		}(i)
	}
	wg.Wait()

	want := service.DeterministicUserID(linkKey)
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("goroutine %d: %v", i, errs[i])
		}
		if ids[i] != want {
			t.Fatalf("goroutine %d: got id %q, want %q", i, ids[i], want)
		}
	}

	// Exactly one User, exactly one link, ACTIVE.
	u := loadUser(t, repo, want)
	if u.GetState() != userv1.State_STATE_ACTIVE {
		t.Fatalf("user state = %v, want ACTIVE", u.GetState())
	}
	if len(u.GetLinkedIdentities()) != 1 {
		t.Fatalf("expected exactly 1 linked identity, got %d: %v", len(u.GetLinkedIdentities()), u.GetLinkedIdentities())
	}
}

func TestResolveOrProvision_UnlinkThenSubjectIsRejected(t *testing.T) {
	// Sanity: the UnlinkIdentity command removes the collection entry.
	repo := newUserRepo()
	links := service.NewMapLinkDirectory()
	p := service.NewIdentityProvisioner(repo, links, service.WithIdentityProvisionerClock(fixedClock()))

	fi := service.FederatedIdentity{IssuerID: "iss-google", Subject: "sub-unlink", Email: "u@example.com"}
	linkKey := service.LinkKey(fi.IssuerID, fi.Subject)
	id, err := p.ResolveOrProvision(context.Background(), fi, &issuerv1.OIDCConfig{
		JitPolicy: issuerv1.OIDCJITPolicy_JIT_AUTO_NO_ROLES,
	})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}

	if _, err := repo.Apply(context.Background(), &userv1.UnlinkIdentity{
		Id:      id,
		Actor:   "test",
		LinkKey: linkKey,
	}); err != nil {
		t.Fatalf("UnlinkIdentity: %v", err)
	}
	u := loadUser(t, repo, id)
	if _, ok := u.GetLinkedIdentities()[linkKey]; ok {
		t.Fatalf("link %q should be removed: %v", linkKey, u.GetLinkedIdentities())
	}
}
