import { useState } from "react";
import { Link } from "react-router-dom";
import { roleClient } from "../clients";
import { State } from "../gen/auth/role/v1/role_pb.js";
import { useAsync, fmtMicroTime, stateName, roleStates } from "../hooks";
import { PageHeader, LinkBtn, Btn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

export default function Roles() {
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const { data: active, error: aErr, loading: aLoading, reload: rA } = useAsync(
    () => roleClient.queryByState(State.ACTIVE),
    [],
  );
  const { data: inactive, error: iErr, loading: iLoading, reload: rI } = useAsync(
    () => roleClient.queryByState(State.INACTIVE),
    [],
  );

  async function exec(action: () => Promise<unknown>) {
    setBusy(true);
    setActionErr(null);
    try {
      await action();
      rA();
      rI();
    } catch (e) {
      setActionErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  const all = [...(active ?? []), ...(inactive ?? [])].sort((a, b) =>
    (a.name || a.id).localeCompare(b.name || b.id),
  );

  return (
    <>
      <PageHeader title="Roles" action={<LinkBtn to="/roles/new">Create Role</LinkBtn>} />
      {(aErr || iErr) && <ErrorBox message={aErr || iErr || ""} />}
      {actionErr && <ErrorBox message={actionErr} />}
      {(aLoading || iLoading) && <Loading />}
      {!aLoading && !iLoading && (
        <Table headers={["Name", "State", "Functions", "Created", ""]}>
          {all.map((r) => (
            <tr key={r.id} className="hover:bg-zinc-50">
              <Td>
                <Link to={`/roles/${r.id}`} className="text-zinc-900 font-medium hover:underline">
                  {r.name || r.id}
                </Link>
              </Td>
              <Td>
                <Badge color={r.state === State.ACTIVE ? "green" : "yellow"}>
                  {stateName(r.state, roleStates)}
                </Badge>
              </Td>
              <Td>{Object.keys(r.functions).length}</Td>
              <Td>{fmtMicroTime(r.createAt)}</Td>
              <Td>
                <div className="flex gap-2 justify-end">
                  {r.state === State.ACTIVE && (
                    <Btn variant="secondary" disabled={busy} onClick={() => exec(() => roleClient.deactivate(r.id))}>
                      Deactivate
                    </Btn>
                  )}
                  {r.state === State.INACTIVE && (
                    <Btn variant="secondary" disabled={busy} onClick={() => exec(() => roleClient.activate(r.id))}>
                      Activate
                    </Btn>
                  )}
                  <Link to={`/roles/${r.id}`} className="text-zinc-500 hover:text-zinc-900 text-xs self-center">
                    View
                  </Link>
                </div>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}
