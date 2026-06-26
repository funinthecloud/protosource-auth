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
- **`loginpage/`** — browser login page served at `GET /` + `POST /` handler that calls Loginer and sets a `shadow` cookie (HttpOnly, Secure, SameSite=Lax) on the parent domain (eTLD+1 via `publicsuffix`). CSRF protection via Origin/Referer validation. Cookie domain auto-derived from Host header. Requires HTTPS.
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

Frontend: prefer `npm --prefix frontend run build` over `npx tsc --noEmit` — the build uses `tsc -b` (composite mode) which catches errors the bare `--noEmit` skips.

## Related repos (locally available)

- `~/Developer/funinthecloud/protosource` — the framework. Indexed by jcodemunch (use `resolve_repo` for the current id). Edit + `go install ./cmd/protoc-gen-protosource{,-ts}` to test plugin changes here without publishing.

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

## Azure deploy (Container Apps + Cosmos + Key Vault HSM)

`tofu/azure-bootstrap/` provisions the tfstate storage account (one-shot per subscription). `tofu/azure/` is the env stack — Premium Key Vault with HSM-backed RSA KEK, Cosmos NoSQL, Container Apps via the upstream `container-app-service` + `cosmos-eventstore` modules (pinned at v0.4.0). The same `cmd/protosource-auth` binary serves both clouds; selection is purely env-driven (`PROTOSOURCE_AUTH_STORE_BACKEND`, `PROTOSOURCE_AUTH_KEY_PROVIDER`, `PROTOSOURCE_AUTH_MASTER_KEY_REF`).

```bash
# One-time bootstrap of tfstate backend
cd tofu/azure-bootstrap && tofu init && tofu apply -var subscription_id=<id>

# Env stack — first apply with the Microsoft quickstart image, then
# push the real image and re-apply:
cd ../azure
tofu init \
  -backend-config="resource_group_name=<bootstrap rg>" \
  -backend-config="storage_account_name=<bootstrap sa>" \
  -backend-config="container_name=tfstate"
tofu apply -var subscription_id=<id> -var issuer_iss=https://auth.example.com

# Build + push image, then re-apply
ACR_LOGIN_SERVER=$(tofu output -raw acr_login_server)
az acr login --name "${ACR_LOGIN_SERVER%%.*}"
cd ../.. && make push-azure CONTAINER_IMAGE="$ACR_LOGIN_SERVER/protosource-auth:dev"
make deploy-azure CONTAINER_IMAGE="$ACR_LOGIN_SERVER/protosource-auth:dev"
```

Production must use `PROTOSOURCE_AUTH_KEY_PROVIDER=azurekeyvault` — the local provider is dev-only.

### Cross-origin SPA cookie scoping

The Azure SPA at `admin-auth.drhayt.com` talks to the API at `auth.fitc.drhayt.com`. The shadow cookie is scoped to the eTLD+1 (`.drhayt.com`) by `loginpage` via `publicsuffix`, which is what lets it flow across both hosts. CORS must set `AllowCredentials: true` (driven by `PROTOSOURCE_AUTH_CORS_ORIGIN`).

### Local Azure-flavor dev

Use the Cosmos emulator + the local key provider:

```bash
docker run --rm -d -p 8081:8081 --name cosmos-emulator \
  mcr.microsoft.com/cosmosdb/linux/azure-cosmos-emulator
export PROTOSOURCE_AUTH_STORE_BACKEND=cosmosdb
export PROTOSOURCE_AUTH_COSMOS_ENDPOINT=https://localhost:8081
export PROTOSOURCE_AUTH_COSMOS_KEY='C2y6yDjf5/R+ob0N8A7Cgv30VRDJIWEHLM+4QDU5DE2nQ9nDuVTqobD4b8mGGyPMbIZnqyMsEcaGQy67XIw/Jw=='
export PROTOSOURCE_AUTH_COSMOS_INSECURE_TLS=1
export PROTOSOURCE_AUTH_LOCAL_MASTER_KEY="$(openssl rand 32 | base64)"
export PROTOSOURCE_AUTH_ISSUER_ISS=https://auth.local
protosource-authmgr ensure-tables
go run ./cmd/protosource-auth
```

### Open follow-ups (not in v1)

- **Private endpoints / custom VNet.** Public endpoints + Managed Identity + RBAC is the current posture. Adding a VNet + private endpoints for Cosmos and Key Vault is additive HCL (a few hundred lines) when a compliance driver appears. The change goes upstream into the protosource modules first.
- **Functions runtime.** Container Apps was chosen for parity with upstream. Azure Functions would require a custom-handler shim; defer unless cost/cold-start tells a different story.

## Lambda deploy

```bash
sam build && sam deploy --guided   # first time
sam build && sam deploy            # subsequent
```

`template.yaml` deploys `provided.al2023` / `arm64` behind API Gateway (`/` for login page + `/{proxy+}` for API). Config via `samconfig.toml`:
- `KmsKeyArn` — full ARN of the KMS key for signing key encryption (not an alias)
- `EventsTableName` / `AggregatesTableName` — default `events` / `aggregates`
- `DomainName` / `CertificateArn` / `HostedZoneId` — custom domain + Route53

Bootstrap before first deploy: `protosource-authmgr bootstrap --admin-email ... --admin-password ...`

## Conventions

- Module path: `github.com/funinthecloud/protosource-auth`
- Go 1.25+, depends on `github.com/funinthecloud/protosource v0.8.0+` (v0.7.1 GH#96/PR#97: by-name singular embedded message events; v0.8.0: multi-cookie responses for the access JWT)
- Generated files under `gen/` are auto-generated — never edit by hand
- Proto files formatted with `clang-format --style=file -i proto/**/*.proto` (NOT `buf format`)
- Protosource field-name contracts bit us in phase 2: aggregates need `create_at` / `create_by` / `modify_at` / `modify_by` (not `created_at`); command fields must name-match event fields for mechanical copying; ADD events embed the element message type (`RoleGrant grant`, `FunctionGrant grant`)
- Singular embedded message events (v0.7.1) are matched to the aggregate field **by name**, not by type: a "set" event carries the populated same-named embed (`Issuer.oidc` ← `OIDCConfigSet.oidc`), a "clear" event carries it empty to nil the field (`OIDCConfigCleared.oidc`). The generator hard-fails if an event embeds a message present on the aggregate under a different field name — keep command/event embed field names identical to the aggregate's

## Function name convention

Role entries use canonical `{proto_package}.{CommandMessageName}` strings. Examples:

- `auth.user.v1.Create`, `auth.user.v1.Lock`, `auth.user.v1.AssignRole`
- `showcase.app.todolist.v1.Create`, `showcase.app.todolist.v1.Archive`
- Wildcards: `auth.user.v1.*`, `auth.**` (no — only single-trailing-`.*` is supported), `*` (super-admin)

See `functions/match.go` for the exact matcher semantics and 28 test cases.

## TODO

See [TODO.md](TODO.md) for remaining work.


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:7510c1e2 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Session Completion

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds
<!-- END BEADS INTEGRATION -->
