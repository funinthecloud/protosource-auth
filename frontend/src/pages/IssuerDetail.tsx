import { useState } from "react";
import { useParams } from "react-router-dom";
import { issuerClient } from "../clients";
import { State } from "../gen/auth/issuer/v1/issuer_pb.js";
import { useAsync, fmtTime, stateName, issuerStates, issuerKinds } from "../hooks";
import { PageHeader, Btn, Badge, Card, DetailRow, Loading, ErrorBox } from "../ui";

export default function IssuerDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, loading, reload } = useAsync(() => issuerClient.get(id!), [id]);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

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
          <DetailRow label="State">
            <Badge color={data.state === State.ACTIVE ? "green" : data.state === State.DEACTIVATED ? "yellow" : "red"}>
              {stateName(data.state, issuerStates)}
            </Badge>
          </DetailRow>
          <DetailRow label="Created">{fmtTime(data.createAt)}</DetailRow>
          <DetailRow label="Modified">{fmtTime(data.modifyAt)}</DetailRow>
        </div>
      </Card>
    </>
  );
}
