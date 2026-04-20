import { useState } from "react";
import { listTokens, post } from "../api";
import { useAuth } from "../auth";
import { useAsync, fmtTime, stateName, tokenStates } from "../hooks";
import { PageHeader, Btn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

export default function Tokens() {
  const { user: me } = useAuth();
  const { data, error, loading, reload } = useAsync(listTokens);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  async function revoke(id: string) {
    setBusy(true);
    setActionErr(null);
    try {
      await post("auth/token/v1/revoke", { id, actor: me.user_id });
      reload();
    } catch (e) {
      setActionErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Tokens" />
      {(error || actionErr) && <ErrorBox message={(error || actionErr)!} />}
      {loading && <Loading />}
      {data && (
        <Table headers={["Token ID", "User ID", "State", "Issued", "Expires", ""]}>
          {data.map((t) => (
            <tr key={t.id} className="hover:bg-zinc-50">
              <Td>
                <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded truncate max-w-32 block">
                  {t.id}
                </code>
              </Td>
              <Td>
                <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{t.user_id}</code>
              </Td>
              <Td>
                <Badge color={t.state === 1 ? "green" : "red"}>
                  {stateName(t.state, tokenStates)}
                </Badge>
              </Td>
              <Td>{fmtTime(t.issued_at)}</Td>
              <Td>{fmtTime(t.expires_at)}</Td>
              <Td>
                {t.state === 1 && (
                  <Btn variant="danger" disabled={busy} onClick={() => revoke(t.id)}>
                    Revoke
                  </Btn>
                )}
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}
