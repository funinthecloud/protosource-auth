# Architecture Review: protosource-auth

**Reviewed:** 2026-05-19  
**Reviewer:** Grok 4.3 (xAI)  
**Commit:** `5b4b7da` (main, clean working tree)  
**Repository:** `funinthecloud/protosource-auth`  
**Method:** Static analysis via jcodemunch indexing tools (`get_repo_health`, `get_tectonic_map`, `get_file_tree`, `get_file_content`, `search_symbols`, `get_dead_code_v2`, `get_coupling_metrics`, `get_dependency_graph`, etc.) + manual deep reading of hand-written layers against the documented design in `Claude.md`.

---

## Executive Summary

protosource-auth is a **shadow-token + wildcard function-grant authorization service** built on the [protosource](https://github.com/funinthecloud/protosource) event-sourcing framework. It is deliberately multi-cloud (AWS DynamoDB + Azure Cosmos + local), multi-deployment (long-running container, AWS Lambda, Azure Container Apps), and multi-consumer (HTTP `authz.Authorizer`, in-process `directauthz`, browser cookie flow).

**Key architectural health metrics (as of review):**
- 182 files, 2,623 symbols, 1,960 functions/methods
- Average cyclomatic complexity: **2.5** (excellent)
- Dependency cycles: **0** (acyclic)
- Dead-code heuristic: ~5.1% (heavily inflated by multi-`main` Go layout; real dead code low)
- Unstable modules: 11
- Top hotspots: generated `<aggregate>mgr/main.go` entry points (codegen artifact) + [app/config.go](app/config.go) `Normalize`
- Overall repo health grade: **A** (composite 90.9)

The design achieves a rare balance: heavy use of code generation for the five core aggregates while keeping all security-critical and cross-aggregate orchestration in a small, hand-written, auditable core.

---

## Separation of Concerns

**Rating: Excellent**

The repository draws extremely crisp boundaries:

| Layer                  | Location                          | Responsibility                                                                 | Size / Nature      |
|------------------------|-----------------------------------|--------------------------------------------------------------------------------|--------------------|
| Generated Aggregates   | `gen/auth/{user,role,token,issuer,key}/v1/` | Per-aggregate event sourcing, CRUD, memory/Dynamo/Cosmos providers, mgr CLIs, clients, Lambda shims | Large, mechanical, never hand-edited |
| Cross-aggregate Workflows | `service/` (`login.go`, `check.go`, `router.go`, `cache.go`, ...) | `Loginer` (credential verify + token + JWT), `Checker` (token deref + role expansion + `functions.MatchAny`) | Small, hand-written, security-critical |
| Composition Root       | `app/` (`app.go`, `config.go`, `backend_*.go`, `bootstrap.go`) | Wiring of repos, `keys.Resolver`, `Loginer`/`Checker`, `loginpage`, HTTP handler; multi-backend & multi-key-provider dispatch | Medium, the only place that knows all variants |
| Domain Services        | `keys/`, `keyproviders/*`, `signers/*`, `credentials/`, `functions/`, `authz/*` | Narrow, focused abstractions (KeyProvider, Signer, TokenSource, Authorizer, wildcard matcher, argon2id) | Tiny and obvious |
| Presentation (Browser) | `loginpage/`                      | HTTPS-only form, CSRF (Origin/Referer), `publicsuffix` eTLD+1 cookie scoping   | Self-contained     |
| Admin Console          | `frontend/` (Vite + TSX + generated clients) | Management UI for users/roles/issuers/keys/tokens                              | Separate deployable |
| Entry Points           | `cmd/protosource-auth{,-lambda,-mgr}/` | Thin binaries; mgr talks directly to the store (no HTTP)                      | Minimal            |

**Why this matters**: the five aggregates cannot express the login and check workflows as single protosource commands. By confining that orchestration to `service/`, the generated surface stays pure and the hand-written surface stays small and reviewable.

**Only notable leakage**: [app/config.go](app/config.go) (393 LOC, 32 cyclomatic) is a god-struct that understands every backend, every key provider, Cosmos/Dynamo aliasing, and validation rules.

---

## SOLID Principles

**Rating: Strong (especially DIP + ISP)**

- **Dependency Inversion** is pervasive:
  - `keys.Resolver` depends only on `KeyRepo` (narrow interface) + `keyproviders.KeyProvider` + `signers.Signer` map.
  - `service.Checker` / `Loginer` depend on `AggregateRepo` slices and `functions.MatchAny`.
  - `app.Run` is the sole composer that knows concrete implementations.

- **Interface Segregation**:
  - `keyproviders.KeyProvider` (only `Name`/`Encrypt`/`Decrypt`).
  - `TokenSource` (pure extraction strategy — Header, Cookie, Chain).
  - `LiveKey` distinguishes signing vs. verify-only at the type level.

- **Open/Closed**:
  - New KMS provider (GCP, OCI, ...) requires only a 3-method implementation + registration in `app/` + config case + tofu.
  - New aggregate would be added by writing one proto + regenerating; no changes to service or keys layers.

- **Single Responsibility**: each package has one job. `functions/match.go` is 48 lines of deliberately simple, exhaustively tested wildcard logic (only trailing `.*` and `*` supported).

- **Liskov Substitution**: all `KeyProvider` and `Signer` implementations are interchangeable at runtime via config.

The dual `authz` adapters (`httpauthz` vs `directauthz`) reuse the identical `TokenSource` abstraction — a textbook example of the Adapter + Strategy patterns.

---

## Scalability

**Rating: Well-engineered for the domain**

- **Stateless processes**: only two in-memory caches (per-day signing keys + TTL-bounded user→function-set). No session affinity required.
- **Key safety under HA** ([keys/resolver.go](keys/resolver.go)): deterministic `kid = "{issuer_id}:{YYYY-MM-DD}:{algorithm}"` + `protosource.ErrAlreadyCreated` race fallback guarantees exactly one writer and safe readers.
- **Authz hot path** ([service/check.go](service/check.go)): cache hit avoids the User + N×Role fan-out entirely. On miss, careful handling of "role deleted after grant" and rich diagnostic logging.
- **Rotation & TTL hygiene**: signing window + verify grace period cleanly decouple key lifetime from token TTL (default 10 h).
- **Deployment polymorphism**:
  - Long-running container (any orchestrator)
  - AWS Lambda + API Gateway (`cmd/protosource-auth-lambda` + wire DI + SAM)
  - Azure Container Apps + Cosmos (`tofu/azure/`)
  - `directauthz` eliminates network hop for co-located Lambdas sharing Dynamo/Cosmos tables.
- **Operational resilience**: `protosource-authmgr` operates directly against the event/aggregate tables and works even when the HTTP service is down or has never run.

**Known limits** (intentional trade-offs):
- Per-process caches mean Lambda cold starts pay the key-decrypt cost.
- Role fan-out on cache miss is N+1 (acceptable because user→role cardinality is tiny in an authz system).
- No shared/distributed cache (keeps operational surface small).

JWTs are cached on the Token aggregate and forwarded so downstream services can verify offline via JWKS — a classic "scale the check path" pattern.

---

## Maintainability

**Rating: High, with two clear areas of debt**

**Strengths**
- Zero dependency cycles + low complexity.
- Outstanding documentation: every public type and the entire phase history live in `Claude.md`.
- Exhaustive tests on the hand-written security kernel (`functions/match_test.go` has 28 cases; resolver race logic is tested).
- `mgr` CLI + bootstrap/recover flows are first-class and offline-capable.
- Code generation removes the 5-aggregate × 2-store × client/mgr/Lambda boilerplate.
- Clear "why" comments in the code (e.g., why `ErrAlreadyCreated` is not an error, why 503 vs 500 on transient failures).

**Technical Debt & Risks**
1. **[app/config.go](app/config.go) `Normalize`** is the dominant hotspot. It encodes 3 backends × 3 key providers × Cosmos quirks × env-alias precedence. This is the single largest threat to long-term maintainability.
2. **Missing architectural guardrails**: no `.jcodemunch.jsonc` `architecture.layers` rules. `get_layer_violations` currently reports "no rules defined." Future drift (e.g., service importing loginpage details, or direct coupling to generated types) will not be caught automatically.
3. **Tectonic map signal** is polluted by one low-cohesion plate (~77 files) anchored on `authz/httpauthz/httpauthz_test.go` because of broad generated imports. This is an artifact, not a real god module, but it reduces the usefulness of structural coupling metrics.
4. **Generated-code surface area**: `gen/` dominates the tree. IDE performance and diff noise are real costs (accepted trade-off).
5. **Multi-entry-point Go layout** defeats generic dead-code and entry-point detectors.
6. **Two distinct UIs**: `loginpage/` (end-user credential login + shadow cookie) vs `frontend/` (admin CRUD console) are completely separate. Easy to conflate on first reading.
7. **Framework coupling**: correct but deep dependence on protosource. A breaking change in the upstream aggregate contract would ripple through both generated and service layers.

---

## Overall Assessment

This is a **mature, production-grade system** whose architecture directly reflects its requirements: pluggable storage, pluggable KMS, pluggable authorization transport (HTTP vs in-process), browser-friendly cookie scoping, and an ops CLI that works when the service is unavailable.

The cut between generated aggregates and hand-written orchestration is exactly right. The pluggable infrastructure (`KeyProvider`, `Signer`, `TokenSource`, `Authorizer`, backends) demonstrates textbook SOLID and makes future cloud or algorithm additions low-risk.

The two highest-leverage improvements are:
- Splitting the monolithic `Config` object.
- Adding machine-enforceable layer rules.

Everything else is either an acceptable consequence of code generation or a minor documentation polish.

**Recommended grade: A (current health metrics already say the same).**

---

## Prioritized Recommendations

### P0 – High Impact, Moderate Effort
- **Refactor `Config`** ([app/config.go](app/config.go)): introduce `StorageConfig`, `KeyProviderConfig`, `BootstrapConfig` (each with its own `Validate()`). Reduce `Normalize` to orchestration only.
- **Add `.jcodemunch.jsonc`** with `architecture.layers` and wire `get_layer_violations` (or equivalent) into CI. Declare at minimum:
  - `service/` may only depend on `keys/`, `functions/`, generated narrow `*Repo` interfaces, and `authz` error sentinels.
  - `app/` is the only package allowed to import concrete backend and provider implementations.
  - `loginpage/` and `frontend/` are presentation layers and may not be imported by service or keys.

### P1 – Important
- Improve static-analysis configuration or add a small `tools/` entry-point manifest so dead-code and coupling tools understand the three `cmd/` mains + Lambda handler.
- Document the distinct purposes and cookie scopes of `loginpage/` vs `frontend/` in the root `README.md`.
- Add a simple health/metrics endpoint (or structured logs) that surfaces function-cache hit rate and average role fan-out so operators can see when the N+1 path is being hit.

### P2 – Nice to Have
- Optional distributed cache (Redis / DynamoDB DAX / Cosmos) behind the function cache, behind a feature flag.
- Consider a `core/` or `domain/` package that makes the trusted hand-written kernel (`service/` + `keys/` + `functions/` + `credentials/`) even more visually distinct from adapters and wiring.
- Explore private-endpoint / VNet support for Azure (already noted as future work in `Claude.md`).

---

## Key Files for Future Reviewers

- Composition & config: [app/app.go](app/app.go), [app/config.go](app/config.go), [app/backend.go](app/backend.go)
- Core workflows: [service/login.go](service/login.go), [service/check.go](service/check.go), [service/router.go](service/router.go), [service/cache.go](service/cache.go)
- Key lifecycle (the most subtle piece): [keys/resolver.go](keys/resolver.go)
- Pluggable infrastructure: [keyproviders/keyprovider.go](keyproviders/keyprovider.go) + `local/`, `awskms/`, `azurekeyvault/`
- Authz contract & adapters: [authz/httpauthz/httpauthz.go](authz/httpauthz/httpauthz.go), [authz/directauthz/directauthz.go](authz/directauthz/directauthz.go)
- Wildcard rules (security boundary): [functions/match.go](functions/match.go)
- Browser security: [loginpage/loginpage.go](loginpage/loginpage.go)
- Operational CLI: [cmd/protosource-authmgr/main.go](cmd/protosource-authmgr/main.go) and `diagnose.go`

---

*This document was generated from a live architectural analysis session. It should be re-run after any significant refactoring of `app/config.go` or the addition of new backends/providers.*