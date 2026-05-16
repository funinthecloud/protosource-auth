import { useState } from "react";
import { tokenClient } from "../clients";
import { State } from "../gen/auth/token/v1/token_pb.js";
import { useAsync, fmtTime, stateName, tokenStates } from "../hooks";
import { PageHeader, Btn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

export default function Tokens() {
  const { data, error, loading, reload } = useAsync(() => tokenClient.queryByState(State.ISSUED));
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  async function revoke(id: string) {
    setBusy(true);
    setActionErr(null);
    try {
      await tokenClient.revoke(id);
      reload();
    } catch (e) {
      setActionErr(e instanceof Error ? e.message : String(e));
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
                <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{t.userId}</code>
              </Td>
              <Td>
                <Badge color={t.state === State.ISSUED ? "green" : "red"}>
                  {stateName(t.state, tokenStates)}
                </Badge>
              </Td>
              <Td>{fmtTime(t.issuedAt)}</Td>
              <Td>{fmtTime(t.expiresAt)}</Td>
              <Td>
                {t.state === State.ISSUED && (
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
