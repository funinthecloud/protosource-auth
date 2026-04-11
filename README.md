# protosource-auth

Shadow-token authentication and authorization service for the [protosource](https://github.com/funinthecloud/protosource) event sourcing framework.

Clients authenticate with an email and password, receive an opaque shadow token, and downstream services dereference that token back to an authenticated user id + forwarded JWT on every protected call. Authorization is a set-membership check against `{proto_package}.{CommandName}` function strings, with wildcard support.

## Run locally

```bash
# 32-byte master key, base64-encoded — wraps signing-key private material.
export PROTOSOURCE_AUTH_LOCAL_MASTER_KEY="$(openssl rand 32 | base64)"

# JWT "iss" claim value.
export PROTOSOURCE_AUTH_ISSUER_ISS="https://auth.local"

# Optional: create an admin user on startup.
export PROTOSOURCE_AUTH_BOOTSTRAP_EMAIL="admin@example.com"
export PROTOSOURCE_AUTH_BOOTSTRAP_PASSWORD="hunter2"

go run ./cmd/protosource-auth
# protosource-auth listening on :8080 (issuer=https://auth.local)
```

### Log in

```bash
curl -s http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"hunter2","issuer":"default"}' \
  | jq
```

```json
{
  "shadow_token": "qVJ7Kc8...",
  "jwt": "eyJhbGciOiJFZERTQSIsImtpZCI6...",
  "expires_at": 1744365600
}
```

### Authorize a downstream call

```bash
TOKEN=qVJ7Kc8...
curl -s http://localhost:8080/authz/check \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"$TOKEN\",\"required_function\":\"showcase.app.todolist.v1.CreateList\"}" \
  | jq
```

```json
{ "user_id": "user-bootstrap-admin", "jwt": "eyJhbGciOiJFZERTQSI..." }
```

## Wiring a downstream service

Replace `allowall.ProviderSet` in your application's wire.Build with an `httpauthz.Authorizer` pointing at this service:

```go
import "github.com/funinthecloud/protosource-auth/authz/httpauthz"

func provideAuthorizer() authz.Authorizer {
    return httpauthz.New("http://localhost:8080")
}

// wire.Build(..., provideAuthorizer, ...)
```

The generated handler will extract the shadow token from the `Authorization: Bearer` header of each incoming request and check it against the canonical `{proto_package}.{CommandMessageName}` function string the plugin stamps at code-generation time.

## Phase 7 limitations

- **Memorystore only.** All state lives in process memory; restarting the binary loses every user, role, token, and signing key. Bootstrap runs on every startup.
- **No mgr CLI yet.** Admin creation is via `BOOTSTRAP_EMAIL` / `BOOTSTRAP_PASSWORD` env vars at startup.
- **No JWKS endpoint yet.** Downstream services cannot verify JWTs offline — they must dereference every call through `/authz/check`.
- **Single-algorithm.** Ed25519 only.

Persistent storage (DynamoDB + Bolt), a proper mgr CLI, JWKS, and RS256 are planned for later phases.

See [CLAUDE.md](CLAUDE.md) for architecture and build instructions.
