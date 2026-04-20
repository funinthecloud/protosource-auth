# TODO

## Operational readiness

- [ ] **JWKS endpoint.** `GET /.well-known/jwks.json?issuer={id}` returning all `STATE_SIGNING` + `STATE_VERIFY_ONLY` public JWKs for an issuer. Unlocks offline JWT verification by downstream services (skip the per-request `/authz/check` network hop for stateless consumers).
- [ ] **OIDC discovery.** `GET /.well-known/openid-configuration` with `issuer`, `jwks_uri`, `token_endpoint`. Cheap addition once JWKS lands.
- [ ] **RS256 signer.** `signers/rs256signer` mirroring the `ed25519signer` shape. Needed for interop with clients that do not support EdDSA.
- [ ] **Multi-algorithm per issuer.** The Issuer aggregate currently carries a single `default_algorithm`. Change to `map<string, AlgorithmGrant> algorithms` so an issuer can sign in parallel (e.g. during RS256 ⇄ EdDSA migration) and the resolver picks per-request.

## KeyProvider ecosystem

- [x] **AWS KMS provider.** `keyproviders/awskms` using direct KMS Encrypt/Decrypt (no envelope — signing keys are under 4KB).
- [ ] **GCP Cloud KMS provider.** `keyproviders/gcpkms` — no `GenerateDataKey` equivalent, use `Encrypt(random)` to produce the wrapped blob.
- [ ] **Azure Key Vault provider.** `keyproviders/azurekv` using wrap/unwrap key operations.
- [ ] **OCI Vault provider.** `keyproviders/ocivault`.

## Security hardening

- [ ] **Real KMS-backed seed secret verification** in the mgr CLI. Phase 9 just checks `PROTOSOURCE_AUTH_SEED_SECRET` is non-empty. A future phase fetches a digest from KMS / Secrets Manager and verifies the operator-supplied value matches — this is the actual gate against "anyone with shell access can recover-admin."
- [ ] **Rate-limit `/login`** by IP and by email (progressive backoff, Redis-backed or in-process LRU).
- [ ] **Cache invalidation on role/user changes.** The `service.functionCache` is TTL-only. A User.Lock or Role.RemoveFunction takes up to 60s to propagate. Options: invalidate in the command evaluator, or add a push notification path (DynamoDB Streams → local cache).
- [ ] **httpauthz client-side retries** on 5xx responses from `/authz/check`. Currently the client bubbles the wrapped error straight up and the generated handler maps it to 503. An exponential-backoff retry with jitter (bounded to a small number of attempts so the handler can still respond quickly) would hide transient auth-service hiccups from downstream callers.

## Auth features

- [ ] **Email verification flow.** New users currently start `STATE_ACTIVE`. Add `STATE_PENDING_VERIFICATION` + a `VerifyEmail` command + per-token email send. Requires an outbound email integration (not currently scoped).
- [ ] **Password reset flow.** `RequestPasswordReset` command creates a short-lived reset Token aggregate; `/password-reset` endpoint consumes it and calls `User.ChangePassword`.
- [ ] **Refresh tokens.** Currently a shadow token is the only bearer; rotating it requires re-login. Add a second token type with a longer TTL that can mint new shadow tokens without re-entering credentials.
- [ ] **MFA enrollment.** TOTP first (per-user secret on the User aggregate); WebAuthn later.
- [ ] **Device grants / session management.** List active tokens per user + mass-revoke.

## Browser / cookie auth

- [x] **Browser login page.** `loginpage/` package serves `GET /` (HTML form) and `POST /` (authenticates + sets `shadow` cookie server-side). Cookie domain auto-derived from Host via publicsuffix eTLD+1. CSRF protection via Origin/Referer same-domain check. Requires HTTPS. Deployed at `auth.drhayt.com`.
- [ ] **Cookie-based token source in downstream authorizers.** The `httpauthz` and `directauthz` authorizers already support `Cookie(name)` token source — consuming apps need to wire `WithTokenSource(httpauthz.Chain(httpauthz.Cookie("shadow"), httpauthz.AuthorizationHeader()))` so both cookies and Bearer headers work.
- [ ] **Logout endpoint.** `POST /logout` or `DELETE /` that revokes the shadow token and clears the cookie (Max-Age=0). Currently users must wait for token expiry.

## Deployment

- [x] **Lambda deployment target.** `cmd/protosource-auth-lambda` with wire-based DI, `awslambda.WrapRouter`, SAM template at `template.yaml`.
- [x] **Table creation via framework.** Uses `dynamodbstore.EnsureTables` from protosource v0.1.5 (deletion protection + PITR enabled).
- [ ] **Health check endpoint.** `GET /healthz` that pings the KeyProvider, the default Issuer's current signing key, and DynamoDB (DescribeTable). Useful for load balancer probes.

## Observability

- [x] **Structured logging for error paths.** `LOGIN_UNAVAILABLE`, `LOGIN_ISSUER_NOT_ACTIVE`, and `CHECK_UNAVAILABLE` log with `slog.ErrorContext` including email, issuer_id, required_function, and full error chain.
- [ ] **Structured logging everywhere.** Remaining `log.Printf` calls should migrate to `log/slog` with per-request trace ids.
- [ ] **Metrics.** Login success/fail rate, `/authz/check` p50/p99, cache hit rate, KMS call counts per day. Prometheus endpoint or CloudWatch Embedded Metrics.
- [ ] **Audit log.** Every Token.Issue / Token.Revoke / User.Lock / Role mutation should be derivable from the event store already, but a SIEM-friendly emission path (Kinesis/EventBridge) would simplify integrations.

## Done ✓

- [x] Phases 2–9: User + Role + Token + Issuer + Key aggregates, credentials, functions matcher, signers interface + ed25519, KeyProvider interface + local, key resolver, Loginer + Checker + Service, httpauthz client, app package, runnable binary, DynamoDB backend, mgr CLI with bootstrap + recover-admin
- [x] End-to-end integration with [todoapp](https://github.com/funinthecloud/todoapp) verified against DynamoDB Local
- [x] Bumped to protosource v0.1.3 — picks up the `authz.UserIDFromContext` precedence in generated handlers + 503 mapping for transient authorizer errors
- [x] Own `/login` + `/authz/check` error mappers aligned: unknown errors return 503 instead of 500
- [x] Lambda deployment with wire-based DI (`cmd/protosource-auth-lambda`, SAM template, API Gateway)
- [x] AWS KMS key provider (`keyproviders/awskms`) — direct Encrypt/Decrypt, no envelope
- [x] Direct in-process authorizer (`authz/directauthz`) wrapping `service.Checker` — no HTTP round-trip for co-deployed Lambdas
- [x] Moved MasterKey validation out of Normalize so mgr CLI works without a master key
- [x] Table creation delegated to `dynamodbstore.EnsureTables` from protosource v0.1.5 (deletion protection + PITR)
- [x] slog error logging on LOGIN_UNAVAILABLE / CHECK_UNAVAILABLE paths
- [x] Bumped to protosource v0.1.5
- [x] Browser login page (`loginpage/`) with server-side cookie, CSRF protection, publicsuffix domain derivation, HTTPS enforcement
- [x] SAM template updated with root path (`/`) route for login page
