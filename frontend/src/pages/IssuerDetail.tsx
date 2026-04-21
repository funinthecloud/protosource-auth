import { useState } from "react";
import { useParams } from "react-router-dom";
import { getIssuer, post } from "../api";
import { useAuth } from "../auth";
import { useAsync, fmtTime, stateName, issuerStates, issuerKinds } from "../hooks";
import { PageHeader, Btn, Badge, Card, DetailRow, Loading, ErrorBox } from "../ui";

export default function IssuerDetail() {
  const { id } = useParams<{ id: string }>();
  const { user: me } = useAuth();
  const { data, error, loading, reload } = useAsync(() => getIssuer(id!), [id]);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  async function exec(path: string, body: Record<string, unknown> = {}) {
    setBusy(true);
    setActionErr(null);
    try {
      await post(path, { id, actor: me.user_id, ...body });
      reload();
    } catch (e) {
      setActionErr(String(e));
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
        title={data.display_name || data.id}
        action={
          <div className="flex gap-2">
            {data.state === 1 && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec("auth/issuer/v1/deactivate")}>
                Deactivate
              </Btn>
            )}
            {data.state === 2 && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec("auth/issuer/v1/reactivate")}>
                Reactivate
              </Btn>
            )}
            {(data.state === 1 || data.state === 2) && (
              <Btn
                variant="danger"
                disabled={busy}
                onClick={() => {
                  if (confirm("Delete this issuer?")) exec("auth/issuer/v1/delete");
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
          <DetailRow label="Display Name">{data.display_name || "-"}</DetailRow>
          <DetailRow label="Kind">{issuerKinds[data.kind] ?? data.kind}</DetailRow>
          <DetailRow label="Algorithm">{data.default_algorithm || "-"}</DetailRow>
          <DetailRow label="JWKS URL">{data.jwks_url || "-"}</DetailRow>
          <DetailRow label="State">
            <Badge color={data.state === 1 ? "green" : data.state === 2 ? "yellow" : "red"}>
              {stateName(data.state, issuerStates)}
            </Badge>
          </DetailRow>
          <DetailRow label="Created">{fmtTime(data.create_at)}</DetailRow>
          <DetailRow label="Modified">{fmtTime(data.modify_at)}</DetailRow>
        </div>
      </Card>
    </>
  );
}
