import { Link } from "react-router-dom";
import { useState } from "react";
import { listKeys, post } from "../api";
import { useAuth } from "../auth";
import { useAsync, fmtTime, stateName, keyStates } from "../hooks";
import { PageHeader, Btn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

export default function Keys() {
  const { user: me } = useAuth();
  const { data, error, loading, reload } = useAsync(listKeys);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  async function exec(path: string, id: string) {
    setBusy(true);
    setActionErr(null);
    try {
      await post(path, { id, actor: me.user_id });
      reload();
    } catch (e) {
      setActionErr(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Keys" />
      {(error || actionErr) && <ErrorBox message={(error || actionErr)!} />}
      {loading && <Loading />}
      {data && (
        <Table headers={["KID", "Algorithm", "State", "Effective", "Signing Until", ""]}>
          {data.map((k) => {
            const color = k.state === 1 ? "green" : k.state === 2 ? "blue" : "zinc";
            return (
              <tr key={k.id} className="hover:bg-zinc-50">
                <Td>
                  <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{k.id}</code>
                </Td>
                <Td>{k.algorithm}</Td>
                <Td>
                  <Badge color={color}>{stateName(k.state, keyStates)}</Badge>
                </Td>
                <Td>{fmtTime(k.effective_at)}</Td>
                <Td>{fmtTime(k.signing_until)}</Td>
                <Td>
                  <div className="flex gap-1">
                    {k.state === 1 && (
                      <Btn variant="secondary" disabled={busy} onClick={() => exec("auth/key/v1/retire", k.id)}>
                        Retire
                      </Btn>
                    )}
                    {k.state === 2 && (
                      <Btn variant="secondary" disabled={busy} onClick={() => exec("auth/key/v1/expire", k.id)}>
                        Expire
                      </Btn>
                    )}
                  </div>
                </Td>
              </tr>
            );
          })}
        </Table>
      )}
    </>
  );
}
