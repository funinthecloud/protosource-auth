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

## Persistent storage — DynamoDB

Set `PROTOSOURCE_AUTH_STORE_BACKEND=dynamodb` to run against DynamoDB instead of the in-memory default. The service needs two tables:

- `protosource-auth-events` — events table, `a` (S) / `v` (N), TTL on `t`
- `protosource-auth-aggregates` — materialized aggregates + opaquedata single-table, `pk` (S) / `sk` (S), 20 GSI pairs (`gsi{N}pk`/`gsi{N}sk`), TTL on `t`

Table names are configurable via `PROTOSOURCE_AUTH_EVENTS_TABLE` / `PROTOSOURCE_AUTH_AGGREGATES_TABLE`. The `app.EnsureTables` helper creates both idempotently with the right schema — useful for local development and tests.

### Against DynamoDB Local

```bash
docker run -d -p 8000:8000 amazon/dynamodb-local
export AWS_ACCESS_KEY_ID=local
export AWS_SECRET_ACCESS_KEY=local
export AWS_REGION=us-east-1
export PROTOSOURCE_AUTH_LOCAL_MASTER_KEY="$(openssl rand 32 | base64)"
export PROTOSOURCE_AUTH_ISSUER_ISS="https://auth.local"
export PROTOSOURCE_AUTH_STORE_BACKEND=dynamodb
export PROTOSOURCE_AUTH_AWS_ENDPOINT=http://localhost:8000
export PROTOSOURCE_AUTH_BOOTSTRAP_EMAIL=admin@example.com
export PROTOSOURCE_AUTH_BOOTSTRAP_PASSWORD=hunter2

go run ./cmd/protosource-auth
```

DynamoDB Local partitions its internal storage by `(region, access-key)`; tables created under one set of credentials are invisible to another. The env vars above keep everything in one logical database.

### Against real AWS

```bash
export AWS_REGION=us-east-1
# credentials from shared profile / instance role
export PROTOSOURCE_AUTH_LOCAL_MASTER_KEY="$(openssl rand 32 | base64)"
export PROTOSOURCE_AUTH_ISSUER_ISS="https://auth.example.com"
export PROTOSOURCE_AUTH_STORE_BACKEND=dynamodb
# tables must already exist — use EnsureTables from a bootstrap script,
# or provision via CloudFormation.

go run ./cmd/protosource-auth
```

### Run the DynamoDB integration test

```bash
docker run -d -p 8000:8000 amazon/dynamodb-local
PROTOSOURCE_AUTH_TEST_DYNAMO_ENDPOINT=http://localhost:8000 go test ./app/...
```

Skipped when the env var is unset, so CI without Docker is unaffected.

## mgr CLI

`protosource-authmgr` is the operational CLI. It talks to the store directly via the protosource aggregate Repository — **no HTTP round-trips to the running service**, so it works when the service is down, before the service has ever run, or when the last admin has been lost.

```bash
export AWS_REGION=us-east-1                    # plus credentials
export PROTOSOURCE_AUTH_LOCAL_MASTER_KEY=...
export PROTOSOURCE_AUTH_ISSUER_ISS=https://auth.example.com
export PROTOSOURCE_AUTH_STORE_BACKEND=dynamodb
export PROTOSOURCE_AUTH_SEED_SECRET=anything   # phase 9 gate: just has to be non-empty

# Create the DynamoDB tables if they do not exist.
protosource-authmgr ensure-tables

# First-run setup on a fresh deployment.
protosource-authmgr bootstrap \
    --admin-email admin@example.com \
    --admin-password hunter2

# Lost-admin recovery. Creates a timestamped second super-admin role
# + user alongside any existing ones. Refuses to run without --force.
protosource-authmgr recover-admin \
    --admin-email new-admin@example.com \
    --admin-password different \
    --force
```

Recovery creates a fresh `role-super-admin-recovery-<timestamp>` role and `user-recovery-admin-<timestamp>` user so the operation is fully additive — the original admin (if it still exists) is untouched and keeps its grants. Every recovery invocation is logged with a loud warning.

The `PROTOSOURCE_AUTH_SEED_SECRET` env var gates bootstrap and recover-admin against accidental invocation. Phase 9 just checks that it is non-empty; a future phase wires it to KMS / Secrets Manager and verifies against a stored digest.

## Current limitations

- **No JWKS endpoint yet.** Downstream services cannot verify JWTs offline — they must dereference every call through `/authz/check`.
- **Single-algorithm.** Ed25519 only.
- **`PROTOSOURCE_AUTH_SEED_SECRET` is not verified** — phase 9 just checks that it is set. A future phase will verify against a KMS-stored digest.

JWKS, RS256, and a real KMS-backed seed secret are planned for later phases.

See [CLAUDE.md](CLAUDE.md) for architecture and build instructions.
