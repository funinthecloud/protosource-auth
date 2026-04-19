# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# protosource-auth

Shadow-token authentication and authorization service built on [protosource](https://github.com/funinthecloud/protosource). Users authenticate with credentials, receive an opaque token (GUID), and downstream services dereference the opaque token against `/authz/check` on every protected call. Authorization is a set-membership check against `{proto_package}.{CommandName}` function strings with wildcard support.

## Aggregates

Five, all defined as protosource protos and code-generated under `gen/auth/`:

| Aggregate | Package | Purpose |
|---|---|---|
| `User` | `auth.user.v1` | identity, argon2id credentials, `map<string, RoleGrant>` collection |
| `Role` | `auth.role.v1` | `map<string, FunctionGrant>` of function strings (with wildcards) |
| `Token` | `auth.token.v1` | opaque GUID (the aggregate id) → user_id + cached JWT, `event_ttl_seconds: 36000` |
| `Issuer` | `auth.issuer.v1` | JWT `iss` metadata; KIND_SELF issuers sign, KIND_EXTERNAL verify only |
| `Key` | `auth.key.v1` | per-issuer/per-day/per-algorithm signing key; deterministic kid `{issuer_id}:{YYYY-MM-DD}:{algorithm}` |

## Runtime layers

- **`credentials/`** — argon2id Hash/Verify (PHC string format, 64MiB/t=3/p=2).
- **`functions/`** — wildcard matcher for function strings. `*` grants everything, `prefix.*` matches anything starting with `prefix.`, otherwise exact. Leading/middle wildcards are treated as literals.
- **`signers/`** — `Signer` interface + `ed25519signer` (EdDSA, RFC 8037 JWK). RS256 is a planned follow-up.
- **`keyproviders/`** — `KeyProvider` interface for envelope-encryption of signing keys. `keyproviders/local` uses XChaCha20-Poly1305 with a 32-byte master key from env. `keyproviders/awskms` uses direct AWS KMS Encrypt/Decrypt (no envelope — signing keys are under 4KB). GCP KMS / Azure / OCI planned.
- **`keys/`** — `Resolver` for lazy per-day key materialization. First call for an (issuer, algorithm, today) generates a keypair, wraps via the KeyProvider, persists the Key aggregate, and caches the plaintext in memory. Race-safe via deterministic kid + `ErrAlreadyCreated` fallback. `VerificationKey` returns a stripped clone with no private material.
- **`service/`** — hand-written `Loginer` and `Checker` + `Service` HTTP adapter registering `POST /login` and `POST /authz/check`. Orchestrates the generated aggregates that cannot be a single protosource command (credential verify spans User + Issuer + Key + Token). Includes `MapDirectory` (in-memory) and `functionCache` (TTL-bounded user→function-set).
- **`authz/httpauthz/`** — HTTP-based `authz.Authorizer` for downstream consumers. POSTs to `/authz/check` with a shadow token and required function, enriches `ctx` with `authz.WithUserID` / `authz.WithJWT` on success. Pluggable `TokenSource` (AuthorizationHeader, Cookie, Chain).
- **`authz/directauthz/`** — in-process `authz.Authorizer` that wraps `*service.Checker` directly against the aggregate repos. No HTTP round-trip — for Lambdas sharing the same DynamoDB tables. Reuses `httpauthz.TokenSource`.
- **`app/`** — `Config` + `Run(ctx, cfg) → *App` assembling everything into an `http.Handler`. `Backend` dispatch for memory or DynamoDB. Startup bootstrap. Public `NewBundle`, `Bootstrap`, `RegisterDefaultIssuer` for the mgr CLI. Table creation uses `dynamodbstore.EnsureTables` from protosource.
- **`cmd/protosource-auth/`** — runnable service binary (HTTP server, local dev).
- **`cmd/protosource-auth-lambda/`** — Lambda entry point using wire-based DI. `awslambda.WrapRouter` + AWS KMS key provider. SAM template at `template.yaml`.
- **`cmd/protosource-authmgr/`** — operational CLI (`ensure-tables`, `bootstrap`, `recover-admin`) that talks to the store directly via the aggregate Repository — no HTTP round-trips to the running service, so it works when the service is down or before it has ever run. Does not require a master key (never touches signing keys).

## Build & Run

```bash
go install github.com/funinthecloud/protosource/cmd/protoc-gen-protosource@latest
buf generate
go build ./...
go test ./...                          # full suite
go test -race ./...                    # under the race detector
go vet ./...
```

## Local dev

```bash
# Required
export PROTOSOURCE_AUTH_LOCAL_MASTER_KEY="$(openssl rand 32 | base64)"
export PROTOSOURCE_AUTH_ISSUER_ISS="https://auth.local"

# Optional: create an admin on first run (memorystore re-creates every start)
export PROTOSOURCE_AUTH_BOOTSTRAP_EMAIL="admin@example.com"
export PROTOSOURCE_AUTH_BOOTSTRAP_PASSWORD="hunter2"

go run ./cmd/protosource-auth      # :8080
```

### Login page local dev

The login page (`GET /`) requires HTTPS (it refuses `POST /` without `X-Forwarded-Proto: https`). To test the full browser flow locally, use a reverse proxy with a self-signed cert, or add hosts file aliases and use `mkcert`:

```bash
# /etc/hosts — point subdomains at loopback
127.0.0.1  auth.local.dev  todoapp.local.dev

# Generate certs (one-time)
mkcert -install
mkcert auth.local.dev todoapp.local.dev

# Run behind caddy, nginx, or similar with the certs
# Then visit https://auth.local.dev/
```

This gives you real subdomain cookie scoping (`.local.dev`) so the shadow cookie flows between `auth.local.dev` and `todoapp.local.dev` exactly as it does in production.

For API-only testing (curl), bypass the login page and POST to `/login` directly — no HTTPS requirement on that endpoint.

See `README.md` for the DynamoDB Local flow and curl examples for `/login` + `/authz/check`.

## mgr CLI

```bash
export PROTOSOURCE_AUTH_SEED_SECRET=anything              # phase 9: just has to be non-empty

protosource-authmgr ensure-tables                         # idempotent table create
protosource-authmgr bootstrap --admin-email ... --admin-password ...
protosource-authmgr recover-admin --admin-email ... --admin-password ... --force
```

Recovery creates a timestamped `role-super-admin-recovery-<ts>` + `user-recovery-admin-<ts>` alongside existing state — fully additive, never destructive. `--force` is required; the original super-admin is untouched.

## Lambda deploy

```bash
sam build && sam deploy --guided   # first time
sam build && sam deploy            # subsequent
```

`template.yaml` deploys `provided.al2023` / `arm64` behind API Gateway `{proxy+}`. Config via `samconfig.toml`:
- `KmsKeyArn` — full ARN of the KMS key for signing key encryption (not an alias)
- `EventsTableName` / `AggregatesTableName` — default `events` / `aggregates`
- `DomainName` / `CertificateArn` / `HostedZoneId` — custom domain + Route53

Bootstrap before first deploy: `protosource-authmgr bootstrap --admin-email ... --admin-password ...`

## Conventions

- Module path: `github.com/funinthecloud/protosource-auth`
- Go 1.25+, depends on `github.com/funinthecloud/protosource v0.1.5+`
- Generated files under `gen/` are auto-generated — never edit by hand
- Proto files formatted with `clang-format --style=file -i proto/**/*.proto` (NOT `buf format`)
- Protosource field-name contracts bit us in phase 2: aggregates need `create_at` / `create_by` / `modify_at` / `modify_by` (not `created_at`); command fields must name-match event fields for mechanical copying; ADD events embed the element message type (`RoleGrant grant`, `FunctionGrant grant`)

## Function name convention

Role entries use canonical `{proto_package}.{CommandMessageName}` strings. Examples:

- `auth.user.v1.Create`, `auth.user.v1.Lock`, `auth.user.v1.AssignRole`
- `showcase.app.todolist.v1.Create`, `showcase.app.todolist.v1.Archive`
- Wildcards: `auth.user.v1.*`, `auth.**` (no — only single-trailing-`.*` is supported), `*` (super-admin)

See `functions/match.go` for the exact matcher semantics and 28 test cases.

## TODO

See [TODO.md](TODO.md) for remaining work.
