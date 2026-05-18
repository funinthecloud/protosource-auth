import { useState } from "react";
import { useParams } from "react-router-dom";
import { post } from "../api";
import { userClient, roleClient } from "../clients";
import { State } from "../gen/auth/user/v1/user_pb.js";
import { State as RoleState } from "../gen/auth/role/v1/role_pb.js";
import { useAsync, fmtTime, fmtMicroTime, stateName, userStates } from "../hooks";
import { PageHeader, Btn, Badge, Card, DetailRow, Table, Td, Loading, ErrorBox } from "../ui";

export default function UserDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, loading, reload } = useAsync(() => userClient.get(id!), [id]);
  const { data: roles } = useAsync(() => roleClient.queryByState(RoleState.ACTIVE), []);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const [roleId, setRoleId] = useState("");
  const [newPass, setNewPass] = useState("");

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

  const stateColor = data.state === State.ACTIVE ? "green" : data.state === State.LOCKED ? "yellow" : "red";

  return (
    <>
      <PageHeader
        title={data.email}
        action={
          <div className="flex gap-2">
            {data.state === State.ACTIVE && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec(() => userClient.lock(id!, "admin"))}>
                Lock
              </Btn>
            )}
            {data.state === State.LOCKED && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec(() => userClient.unlock(id!))}>
                Unlock
              </Btn>
            )}
            {(data.state === State.ACTIVE || data.state === State.LOCKED) && (
              <Btn
                variant="danger"
                disabled={busy}
                onClick={() => {
                  if (confirm("Delete this user?")) exec(() => userClient.delete(id!));
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
          <DetailRow label="Email">{data.email}</DetailRow>
          <DetailRow label="State">
            <Badge color={stateColor}>{stateName(data.state, userStates)}</Badge>
          </DetailRow>
          <DetailRow label="Created">{fmtMicroTime(data.createAt)}</DetailRow>
          <DetailRow label="Modified">{fmtMicroTime(data.modifyAt)}</DetailRow>
        </div>
      </Card>

      <Card>
        <div className="p-4">
          <h2 className="text-sm font-semibold text-zinc-900 mb-3">Change Password</h2>
          <div className="flex gap-2">
            <input
              type="password"
              placeholder="New password"
              value={newPass}
              onChange={(e) => setNewPass(e.target.value)}
              className="border border-zinc-300 rounded px-3 py-1.5 text-sm flex-1"
            />
            <Btn
              disabled={busy || !newPass}
              onClick={async () => {
                await exec(() => post("admin/user/changepassword", { id, password: newPass }));
                setNewPass("");
              }}
            >
              Update
            </Btn>
          </div>
        </div>
      </Card>

      <Card>
        <div className="p-4">
          <h2 className="text-sm font-semibold text-zinc-900 mb-3">Roles</h2>
          {Object.keys(data.roles).length > 0 ? (
            <Table headers={["Role ID", "Assigned", ""]}>
              {Object.values(data.roles).map((r) => (
                <tr key={r.roleId}>
                  <Td>{r.roleId}</Td>
                  <Td>{fmtTime(r.assignedAt)}</Td>
                  <Td>
                    <Btn
                      variant="danger"
                      disabled={busy}
                      onClick={() => exec(() => userClient.revokeRole(id!, r.roleId))}
                    >
                      Revoke
                    </Btn>
                  </Td>
                </tr>
              ))}
            </Table>
          ) : (
            <p className="text-sm text-zinc-400">No roles assigned.</p>
          )}
          <div className="flex gap-2 mt-3">
            <select
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
              className="border border-zinc-300 rounded px-3 py-1.5 text-sm flex-1"
              disabled={!roles}
            >
              <option value="">{roles ? "Select a role…" : "Loading roles…"}</option>
              {roles
                ?.filter((r) => !(r.id in data.roles))
                .map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name ? `${r.name} (${r.id})` : r.id}
                  </option>
                ))}
            </select>
            <Btn
              disabled={busy || !roleId}
              onClick={() => {
                exec(() =>
                  userClient.assignRole(id!, {
                    $typeName: "auth.user.v1.RoleGrant",
                    roleId,
                    assignedAt: BigInt(Math.floor(Date.now() / 1000)),
                  }),
                );
                setRoleId("");
              }}
            >
              Assign Role
            </Btn>
          </div>
        </div>
      </Card>
    </>
  );
}
