import { useState } from "react";
import { issuerClient } from "../clients";
import { post } from "../api";
import { OIDCJITPolicy } from "../gen/auth/issuer/v1/issuer_pb.js";
import type { Issuer } from "../gen/auth/issuer/v1/issuer_pb.js";
import { issuerJitPolicies } from "../hooks";
import { Btn, Card, Badge, ErrorBox } from "../ui";

// IssuerOIDCForm is the admin editor for a KIND_EXTERNAL issuer's OIDC
// client config (federation). It is intentionally write-only for the
// client_secret: the secret is never read back from the server, so the
// field is blank on load and only a non-empty value is sent on save.
//
// SECRET HANDLING / BACKEND CONTRACT
// ----------------------------------
// The browser cannot wrap (encrypt) the client secret — that happens
// server-side via service.OIDCConfigurator, which reuses the KeyProvider
// exactly like signing keys. We therefore do NOT call the generated
// issuerClient.setOIDCConfig() from here, for two reasons:
//
//  1. We must never place a plaintext secret into the OIDCConfig
//     wrapped_client_secret bytes field.
//  2. OIDCConfigSet copies the whole `oidc` sub-message by name (protosource
//     v0.7.1 singular-embed semantics). Sending an OIDCConfig with an empty
//     wrapped_client_secret would CLOBBER a previously-stored secret. Only the
//     server (OIDCConfigurator.Set) knows how to carry the prior wrapped
//     secret forward when the plaintext field is left blank.
//
// So the entire config — including the write-only plaintext secret — is POSTed
// to `POST /admin/issuer/setoidc` (service.AdminIssuer), which mirrors the
// existing admin/user/create password path: it authorizes
// "admin.issuer.v1.SetOIDCConfig", decodes the snake_case body below (matching
// service.SetRequest), and calls service.OIDCConfigurator.Set — which encrypts
// the secret and, when client_secret is omitted/empty, preserves the existing
// wrapped secret. The "Remove OIDC config" button uses the generated
// ClearOIDCConfig command directly.
const SET_OIDC_ENDPOINT = "admin/issuer/setoidc";

type EndpointMode = "discovery" | "pinned";

type ClaimRow = { key: string; value: string };

function claimMapToRows(m: { [k: string]: string } | undefined): ClaimRow[] {
  const rows = Object.entries(m ?? {}).map(([key, value]) => ({ key, value }));
  if (rows.length === 0) {
    // Seed with the email_at_link claim the JIT policies depend on.
    return [{ key: "email_at_link", value: "email" }];
  }
  return rows;
}

const inputCls = "w-full border border-zinc-300 rounded px-3 py-1.5 text-sm";
const labelCls = "block text-sm font-medium text-zinc-700 mb-1";

export default function IssuerOIDCForm({
  issuer,
  onSaved,
  onCancel,
}: {
  issuer: Issuer;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const existing = issuer.oidc;
  const hasSecret = !!existing && existing.wrappedClientSecret.length > 0;

  const [clientId, setClientId] = useState(existing?.clientId ?? "");
  const [clientSecret, setClientSecret] = useState("");
  const [mode, setMode] = useState<EndpointMode>(
    existing && !existing.discoveryUrl && existing.authorizationEndpoint ? "pinned" : "discovery",
  );
  const [discoveryUrl, setDiscoveryUrl] = useState(existing?.discoveryUrl ?? "");
  const [authEndpoint, setAuthEndpoint] = useState(existing?.authorizationEndpoint ?? "");
  const [tokenEndpoint, setTokenEndpoint] = useState(existing?.tokenEndpoint ?? "");
  const [jwksUri, setJwksUri] = useState(existing?.jwksUri ?? "");
  const [issuerStr, setIssuerStr] = useState(existing?.issuer ?? "");
  const [audiences, setAudiences] = useState((existing?.allowedAudiences ?? []).join("\n"));
  const [claims, setClaims] = useState<ClaimRow[]>(claimMapToRows(existing?.claimMap));
  const [jitPolicy, setJitPolicy] = useState<OIDCJITPolicy>(existing?.jitPolicy ?? OIDCJITPolicy.JIT_REJECT);
  const [jitDefaultRoleId, setJitDefaultRoleId] = useState(existing?.jitDefaultRoleId ?? "");
  const [jitDomain, setJitDomain] = useState(existing?.jitDomain ?? "");

  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function setClaim(i: number, patch: Partial<ClaimRow>) {
    setClaims((rows) => rows.map((r, idx) => (idx === i ? { ...r, ...patch } : r)));
  }
  function addClaim() {
    setClaims((rows) => [...rows, { key: "", value: "" }]);
  }
  function removeClaim(i: number) {
    setClaims((rows) => rows.filter((_, idx) => idx !== i));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);

    const claimMap: Record<string, string> = {};
    for (const { key, value } of claims) {
      const k = key.trim();
      if (k) claimMap[k] = value.trim();
    }

    const body: Record<string, unknown> = {
      issuer_id: issuer.id,
      client_id: clientId.trim(),
      discovery_url: mode === "discovery" ? discoveryUrl.trim() : "",
      authorization_endpoint: mode === "pinned" ? authEndpoint.trim() : "",
      token_endpoint: mode === "pinned" ? tokenEndpoint.trim() : "",
      jwks_uri: mode === "pinned" ? jwksUri.trim() : "",
      issuer: mode === "pinned" ? issuerStr.trim() : "",
      allowed_audiences: audiences
        .split("\n")
        .map((s) => s.trim())
        .filter(Boolean),
      claim_map: claimMap,
      jit_policy: jitPolicy,
      jit_default_role_id: jitDefaultRoleId.trim(),
      jit_domain: jitPolicy === OIDCJITPolicy.JIT_DOMAIN_RULE ? jitDomain.trim() : "",
    };
    // Write-only: only send a secret when the admin typed a new one.
    if (clientSecret) body.client_secret = clientSecret;

    try {
      await post(SET_OIDC_ENDPOINT, body);
      onSaved();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  async function handleClear() {
    if (!confirm("Remove OIDC config from this issuer? This disables federation for it.")) return;
    setBusy(true);
    setError(null);
    try {
      await issuerClient.clearOIDCConfig(issuer.id);
      onSaved();
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card>
      {error && <ErrorBox message={error} />}
      <form onSubmit={handleSubmit} className="p-4 space-y-4">
        <div className="rounded border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
          The client secret is write-only: it is encrypted server-side (via{" "}
          <code>POST /{SET_OIDC_ENDPOINT}</code>) and never read back. Leave it blank to keep the
          current value.
        </div>

        <div>
          <label className={labelCls}>Client ID</label>
          <input
            type="text"
            required
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            className={inputCls}
          />
        </div>

        <div>
          <label className={labelCls}>
            Client Secret{" "}
            {hasSecret ? (
              <Badge color="green">configured (write-only)</Badge>
            ) : (
              <Badge color="zinc">not set</Badge>
            )}
          </label>
          <input
            type="password"
            autoComplete="new-password"
            placeholder={hasSecret ? "Leave blank to keep current secret" : "Enter client secret"}
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            className={inputCls}
          />
        </div>

        <div>
          <label className={labelCls}>Endpoints</label>
          <div className="flex gap-4 mb-2 text-sm">
            <label className="flex items-center gap-1">
              <input
                type="radio"
                name="endpointMode"
                checked={mode === "discovery"}
                onChange={() => setMode("discovery")}
              />
              Discovery URL
            </label>
            <label className="flex items-center gap-1">
              <input
                type="radio"
                name="endpointMode"
                checked={mode === "pinned"}
                onChange={() => setMode("pinned")}
              />
              Pinned endpoints
            </label>
          </div>
          {mode === "discovery" ? (
            <input
              type="url"
              placeholder="https://idp.example.com/.well-known/openid-configuration"
              value={discoveryUrl}
              onChange={(e) => setDiscoveryUrl(e.target.value)}
              className={inputCls}
            />
          ) : (
            <div className="space-y-2">
              <input
                type="url"
                placeholder="Authorization endpoint"
                value={authEndpoint}
                onChange={(e) => setAuthEndpoint(e.target.value)}
                className={inputCls}
              />
              <input
                type="url"
                placeholder="Token endpoint"
                value={tokenEndpoint}
                onChange={(e) => setTokenEndpoint(e.target.value)}
                className={inputCls}
              />
              <input
                type="url"
                placeholder="JWKS URI"
                value={jwksUri}
                onChange={(e) => setJwksUri(e.target.value)}
                className={inputCls}
              />
              <input
                type="url"
                placeholder="Issuer (iss) - required for pinned mode"
                value={issuerStr}
                onChange={(e) => setIssuerStr(e.target.value)}
                className={inputCls}
              />
            </div>
          )}
        </div>

        <div>
          <label className={labelCls}>Allowed Audiences (one per line)</label>
          <textarea
            rows={2}
            value={audiences}
            onChange={(e) => setAudiences(e.target.value)}
            className={inputCls}
          />
        </div>

        <div>
          <label className={labelCls}>Claim Map (internal name → IdP claim)</label>
          <div className="space-y-2">
            {claims.map((row, i) => (
              <div key={i} className="flex gap-2">
                <input
                  type="text"
                  placeholder="internal (e.g. email_at_link)"
                  value={row.key}
                  onChange={(e) => setClaim(i, { key: e.target.value })}
                  className={inputCls}
                />
                <input
                  type="text"
                  placeholder="IdP claim (e.g. email)"
                  value={row.value}
                  onChange={(e) => setClaim(i, { value: e.target.value })}
                  className={inputCls}
                />
                <Btn variant="secondary" onClick={() => removeClaim(i)}>
                  −
                </Btn>
              </div>
            ))}
          </div>
          <div className="mt-2">
            <Btn variant="secondary" onClick={addClaim}>
              + Add claim
            </Btn>
          </div>
        </div>

        <div>
          <label className={labelCls}>JIT Policy</label>
          <select
            value={String(jitPolicy)}
            onChange={(e) => setJitPolicy(Number(e.target.value) as OIDCJITPolicy)}
            className={inputCls}
          >
            {Object.entries(issuerJitPolicies).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>

        {jitPolicy === OIDCJITPolicy.JIT_DOMAIN_RULE && (
          <div>
            <label className={labelCls}>JIT Domain</label>
            <input
              type="text"
              placeholder="example.com or .corp.example.com"
              value={jitDomain}
              onChange={(e) => setJitDomain(e.target.value)}
              className={inputCls}
            />
          </div>
        )}

        <div>
          <label className={labelCls}>JIT Default Role ID</label>
          <input
            type="text"
            placeholder="role granted to JIT-provisioned users"
            value={jitDefaultRoleId}
            onChange={(e) => setJitDefaultRoleId(e.target.value)}
            className={inputCls}
          />
        </div>

        <div className="flex gap-2 pt-2 border-t border-zinc-100">
          <Btn type="submit" disabled={busy}>
            Save OIDC Config
          </Btn>
          <Btn variant="secondary" disabled={busy} onClick={onCancel}>
            Cancel
          </Btn>
          {hasSecret && (
            <Btn variant="danger" disabled={busy} onClick={handleClear}>
              Remove OIDC config
            </Btn>
          )}
        </div>
      </form>
    </Card>
  );
}
