import { useState } from "react";
import { keyClient } from "../clients";
import { State } from "../gen/auth/key/v1/key_pb.js";
import { useAsync, fmtTime, stateName, keyStates } from "../hooks";
import { PageHeader, Btn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

export default function Keys() {
  const { data, error, loading, reload } = useAsync(() => keyClient.queryByState(State.SIGNING));
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

  return (
    <>
      <PageHeader title="Keys" />
      {(error || actionErr) && <ErrorBox message={(error || actionErr)!} />}
      {loading && <Loading />}
      {data && (
        <Table headers={["KID", "Algorithm", "State", "Effective", "Signing Until", ""]}>
          {data.map((k) => {
            const color = k.state === State.SIGNING ? "green" : k.state === State.VERIFY_ONLY ? "blue" : "zinc";
            return (
              <tr key={k.id} className="hover:bg-zinc-50">
                <Td>
                  <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{k.id}</code>
                </Td>
                <Td>{k.algorithm}</Td>
                <Td>
                  <Badge color={color}>{stateName(k.state, keyStates)}</Badge>
                </Td>
                <Td>{fmtTime(k.effectiveAt)}</Td>
                <Td>{fmtTime(k.signingUntil)}</Td>
                <Td>
                  <div className="flex gap-1">
                    {k.state === State.SIGNING && (
                      <Btn variant="secondary" disabled={busy} onClick={() => exec(() => keyClient.retire(k.id))}>
                        Retire
                      </Btn>
                    )}
                    {k.state === State.VERIFY_ONLY && (
                      <Btn variant="secondary" disabled={busy} onClick={() => exec(() => keyClient.expire(k.id))}>
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
