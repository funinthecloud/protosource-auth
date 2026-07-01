import { useState } from "react";
import { useParams } from "react-router-dom";
import { issuerClient } from "../clients";
import { Kind, State } from "../gen/auth/issuer/v1/issuer_pb.js";
import { useAsync, fmtMicroTime, stateName, issuerStates, issuerKinds, issuerJitPolicies } from "../hooks";
import { PageHeader, Btn, Badge, Card, DetailRow, Loading, ErrorBox } from "../ui";
import IssuerOIDCForm from "./IssuerOIDCForm";

export default function IssuerDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, loading, reload } = useAsync(() => issuerClient.get(id!), [id]);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [editOidc, setEditOidc] = useState(false);

  async function exec(action: () => Promise<unknown>) {
    setBusy(true);
    setActionErr(null);
    try {
      await action();
      reload();
    } catch (e) {
      setActionErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  if (loading) return <Loading />;
  if (error) return <ErrorBox message={error} />;
  if (!data) return null;

  return (
    <>
      <PageHeader
        title={data.displayName || data.id}
        action={
          <div className="flex gap-2">
            {data.state === State.ACTIVE && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec(() => issuerClient.deactivate(id!))}>
                Deactivate
              </Btn>
            )}
            {data.state === State.DEACTIVATED && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec(() => issuerClient.reactivate(id!))}>
                Reactivate
              </Btn>
            )}
            {(data.state === State.ACTIVE || data.state === State.DEACTIVATED) && (
              <Btn
                variant="danger"
                disabled={busy}
                onClick={() => {
                  if (confirm("Delete this issuer?")) exec(() => issuerClient.delete(id!));
                }}
              >
                Delete
              </Btn>
            )}
          </div>
        }
      />
      {actionErr && <ErrorBox message={actionErr} />}

      <Card>
        <div className="p-4">
          <DetailRow label="ID">{data.id}</DetailRow>
          <DetailRow label="ISS">
            <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{data.iss}</code>
          </DetailRow>
          <DetailRow label="Display Name">{data.displayName || "-"}</DetailRow>
          <DetailRow label="Kind">{issuerKinds[data.kind] ?? data.kind}</DetailRow>
          <DetailRow label="Algorithm">{data.defaultAlgorithm || "-"}</DetailRow>
          <DetailRow label="JWKS URL">{data.jwksUrl || "-"}</DetailRow>
          {data.kind === Kind.EXTERNAL && data.oidc && (
            <>
              <DetailRow label="OIDC Client ID">{data.oidc.clientId || "-"}</DetailRow>
              <DetailRow label="OIDC Secret">{data.oidc.wrappedClientSecret && data.oidc.wrappedClientSecret.length > 0 ? <Badge color="green">configured (write-only)</Badge> : "-"}</DetailRow>
              <DetailRow label="OIDC Discovery/Endpoints">{data.oidc.discoveryUrl || data.oidc.authorizationEndpoint || "-"}</DetailRow>
              <DetailRow label="JIT Policy">{stateName(data.oidc.jitPolicy ?? 0, issuerJitPolicies)}</DetailRow>
            </>
          )}
          <DetailRow label="State">
            <Badge color={data.state === State.ACTIVE ? "green" : data.state === State.DEACTIVATED ? "yellow" : "red"}>
              {stateName(data.state, issuerStates)}
            </Badge>
          </DetailRow>
          <DetailRow label="Created">{fmtMicroTime(data.createAt)}</DetailRow>
          <DetailRow label="Modified">{fmtMicroTime(data.modifyAt)}</DetailRow>
        </div>
      </Card>

      {data.kind === Kind.EXTERNAL && (
        <>
          <div className="px-6">
            <h2 className="text-sm font-semibold text-zinc-900">OIDC Federation</h2>
            <p className="text-xs text-zinc-500 mt-0.5">
              Client config for verifying / federating logins from this external issuer.
            </p>
          </div>
          {editOidc ? (
            <IssuerOIDCForm
              issuer={data}
              onSaved={() => {
                setEditOidc(false);
                reload();
              }}
              onCancel={() => setEditOidc(false)}
            />
          ) : (
            <Card>
              <div className="p-4">
                <Btn onClick={() => setEditOidc(true)}>{data.oidc ? "Edit OIDC config" : "Add OIDC config"}</Btn>
              </div>
            </Card>
          )}
        </>
      )}
    </>
  );
}
