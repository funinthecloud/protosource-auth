# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# protosource-auth

A shadow-token authentication and authorization service built on the [protosource](https://github.com/funinthecloud/protosource) event sourcing framework. Users authenticate with credentials, receive an opaque token (GUID), and the backend dereferences the opaque token to the real JWT on every protected call. Authorization is a set-membership check against `{proto_package}.{CommandName}` function strings.

## Architecture (in progress)

Five aggregates, all defined as protosource protos and code-generated:

| Aggregate | Purpose |
|---|---|
| `User` | identity, argon2id credentials, collection of role ids |
| `Role` | collection of function string grants (with wildcards) |
| `Token` | opaque GUID → user id + cached JWT, 10h event TTL |
| `Issuer` | JWT iss metadata; SELF issuers own signing keys, EXTERNAL verify only |
| `PublicPrivateKey` | per-issuer/per-day key, wrapped private via KeyProvider |

Phase 2 of the plan covers only `User` + argon2id credential helpers. Additional aggregates land in subsequent phases.

## Build & Run

```bash
go install ./cmd/protoc-gen-protosource   # one-time, from protosource repo
buf generate                                # regenerate Go from proto/
go build ./...
go test ./...
go vet ./...
```

## Proto Layout

```
proto/auth/user/v1/user.proto      # package auth.user.v1
```

Generated Go lands under `gen/auth/user/v1/...` via the `module=` buf option. Hand-written domain helpers (argon2id, etc.) live in top-level packages like `credentials/`.

## Conventions

- Module path: `github.com/funinthecloud/protosource-auth`
- Go 1.25+
- Generated files under `gen/` are auto-generated — never edit by hand
- Proto files are formatted with `clang-format --style=file -i proto/**/*.proto` (NOT `buf format`)
- Depends on `github.com/funinthecloud/protosource` for the event sourcing framework and the `authz.Authorizer` interface that downstream consumers will wire in via `httpauthz` once that package lands

## Function Name Convention

Role entries use canonical function names derived from the proto package and command message name. For this service, that means:

- `auth.user.v1.Create`
- `auth.user.v1.AssignRole`
- `auth.user.v1.Lock`
- etc.

Role entries for downstream services (todoapp, etc.) look like `showcase.app.todolist.v1.Create`. Wildcards (`auth.user.v1.*`, `*`) are supported at check time.
