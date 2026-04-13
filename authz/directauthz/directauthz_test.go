package directauthz_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/funinthecloud/protosource"
	"github.com/funinthecloud/protosource/authz"
	"github.com/funinthecloud/protosource/serializers/protobinaryserializer"
	"github.com/funinthecloud/protosource/stores/memorystore"

	"github.com/funinthecloud/protosource-auth/authz/directauthz"
	"github.com/funinthecloud/protosource-auth/authz/httpauthz"
	"github.com/funinthecloud/protosource-auth/credentials"
	issuerv1 "github.com/funinthecloud/protosource-auth/gen/auth/issuer/v1"
	keyv1 "github.com/funinthecloud/protosource-auth/gen/auth/key/v1"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	tokenv1 "github.com/funinthecloud/protosource-auth/gen/auth/token/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
	"github.com/funinthecloud/protosource-auth/keyproviders/local"
	"github.com/funinthecloud/protosource-auth/keys"
	"github.com/funinthecloud/protosource-auth/service"
	"github.com/funinthecloud/protosource-auth/signers"
	"github.com/funinthecloud/protosource-auth/signers/ed25519signer"
)

type rig struct {
	auth    *directauthz.Authorizer
	checker *service.Checker
	loginer *service.Loginer
}

type fakeDirectory struct {
	emails map[string]string
}

func (d *fakeDirectory) FindByEmail(_ context.Context, email string) (string, error) {
	if id, ok := d.emails[email]; ok {
		return id, nil
	}
	return "", errors.New("not found")
}

func newRig(t *testing.T) *rig {
	t.Helper()

	serializer := protobinaryserializer.NewSerializer()

	userRepo := userv1.NewRepository(memorystore.New(userv1.SnapshotEveryNEvents), serializer)
	roleRepo := rolev1.NewRepository(memorystore.New(rolev1.SnapshotEveryNEvents), serializer)
	issuerRepo := issuerv1.NewRepository(memorystore.New(0), serializer)
	keyRepo := keyv1.NewRepository(memorystore.New(0), serializer)
	tokenRepo := tokenv1.NewRepository(memorystore.New(0), serializer)

	masterKey, err := local.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey: %v", err)
	}
	provider, err := local.New(masterKey)
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}

	fixed := time.Date(2026, 4, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return fixed }

	resolver := keys.NewResolver(
		keyRepo, provider, "local-master",
		map[string]signers.Signer{ed25519signer.Algorithm: ed25519signer.Signer{}},
		keys.WithClock(clock),
	)

	dir := &fakeDirectory{emails: make(map[string]string)}
	loginer := service.NewLoginer(userRepo, issuerRepo, tokenRepo, dir, resolver, service.WithLoginerClock(clock))
	checker := service.NewChecker(tokenRepo, userRepo, roleRepo, service.WithCheckerClock(clock))

	ctx := context.Background()

	if _, err := issuerRepo.Apply(ctx, &issuerv1.Register{
		Id: "issuer-self", Actor: "bootstrap",
		Iss: "https://auth.example.com", DisplayName: "Example Auth",
		Kind: issuerv1.Kind_KIND_SELF, DefaultAlgorithm: ed25519signer.Algorithm,
	}); err != nil {
		t.Fatalf("seed issuer: %v", err)
	}

	if _, err := roleRepo.Apply(ctx, &rolev1.Create{
		Id: "role-admin", Actor: "bootstrap", Name: "admin",
	}); err != nil {
		t.Fatalf("seed role: %v", err)
	}
	for _, fn := range []string{"auth.user.v1.Create", "showcase.app.todolist.v1.*"} {
		if _, err := roleRepo.Apply(ctx, &rolev1.AddFunction{
			Id: "role-admin", Actor: "bootstrap",
			Grant: &rolev1.FunctionGrant{Function: fn, GrantedAt: fixed.Unix()},
		}); err != nil {
			t.Fatalf("seed AddFunction %q: %v", fn, err)
		}
	}

	hash, err := credentials.Hash("hunter2")
	if err != nil {
		t.Fatalf("seed hash: %v", err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.Create{
		Id: "user-alice", Actor: "bootstrap",
		Email: "alice@example.com", PasswordHash: hash,
	}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := userRepo.Apply(ctx, &userv1.AssignRole{
		Id: "user-alice", Actor: "bootstrap",
		Grant: &userv1.RoleGrant{RoleId: "role-admin", AssignedAt: fixed.Unix()},
	}); err != nil {
		t.Fatalf("seed AssignRole: %v", err)
	}
	dir.emails["alice@example.com"] = "user-alice"

	return &rig{
		auth:    directauthz.New(checker),
		checker: checker,
		loginer: loginer,
	}
}

func login(t *testing.T, r *rig) string {
	t.Helper()
	resp, err := r.loginer.Login(context.Background(), service.LoginRequest{
		Email: "alice@example.com", Password: "hunter2", IssuerID: "issuer-self",
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return resp.ShadowToken
}

func bearerReq(token string) protosource.Request {
	return protosource.Request{
		Headers: map[string]string{"Authorization": "Bearer " + token},
	}
}

func TestAuthorizePermitsGrantedFunction(t *testing.T) {
	r := newRig(t)
	token := login(t, r)

	ctx, err := r.auth.Authorize(context.Background(), bearerReq(token), "auth.user.v1.Create")
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if authz.UserIDFromContext(ctx) != "user-alice" {
		t.Errorf("UserIDFromContext = %q, want user-alice", authz.UserIDFromContext(ctx))
	}
	if authz.JWTFromContext(ctx) == "" {
		t.Errorf("JWTFromContext is empty")
	}
}

func TestAuthorizePermitsWildcard(t *testing.T) {
	r := newRig(t)
	token := login(t, r)

	_, err := r.auth.Authorize(context.Background(), bearerReq(token), "showcase.app.todolist.v1.Archive")
	if err != nil {
		t.Errorf("Authorize(wildcard): %v", err)
	}
}

func TestAuthorizeForbidsUngrantedFunction(t *testing.T) {
	r := newRig(t)
	token := login(t, r)

	_, err := r.auth.Authorize(context.Background(), bearerReq(token), "auth.role.v1.Delete")
	if !errors.Is(err, authz.ErrForbidden) {
		t.Errorf("Authorize(ungranted) = %v, want ErrForbidden", err)
	}
}

func TestAuthorizeUnauthenticatedWhenNoToken(t *testing.T) {
	r := newRig(t)
	_, err := r.auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{}},
		"auth.user.v1.Create",
	)
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Authorize(no token) = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthorizeUnauthenticatedWhenTokenInvalid(t *testing.T) {
	r := newRig(t)
	_, err := r.auth.Authorize(context.Background(), bearerReq("not-a-real-token"), "auth.user.v1.Create")
	if !errors.Is(err, authz.ErrUnauthenticated) {
		t.Errorf("Authorize(bad token) = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthorizeWithCookieTokenSource(t *testing.T) {
	r := newRig(t)
	r.auth = directauthz.New(r.checker, directauthz.WithTokenSource(httpauthz.Cookie("shadow")))
	token := login(t, r)

	_, err := r.auth.Authorize(
		context.Background(),
		protosource.Request{Headers: map[string]string{"Cookie": "other=x; shadow=" + token + "; also=y"}},
		"auth.user.v1.Create",
	)
	if err != nil {
		t.Errorf("Authorize(cookie source): %v", err)
	}
}
