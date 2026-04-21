import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getUser, post } from "../api";
import { useAuth } from "../auth";
import { useAsync, fmtTime, stateName, userStates } from "../hooks";
import { PageHeader, Btn, Badge, Card, DetailRow, Table, Td, Loading, ErrorBox } from "../ui";

export default function UserDetail() {
  const { id } = useParams<{ id: string }>();
  const { user: me } = useAuth();
  const navigate = useNavigate();
  const { data, error, loading, reload } = useAsync(() => getUser(id!), [id]);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);

  const [roleId, setRoleId] = useState("");
  const [newPass, setNewPass] = useState("");

  async function exec(path: string, body: Record<string, unknown>) {
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

  const stateColor = data.state === 1 ? "green" : data.state === 2 ? "yellow" : "red";

  return (
    <>
      <PageHeader
        title={data.email}
        action={
          <div className="flex gap-2">
            {data.state === 1 && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec("auth/user/v1/lock", { reason: "admin" })}>
                Lock
              </Btn>
            )}
            {data.state === 2 && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec("auth/user/v1/unlock", {})}>
                Unlock
              </Btn>
            )}
            {(data.state === 1 || data.state === 2) && (
              <Btn
                variant="danger"
                disabled={busy}
                onClick={() => {
                  if (confirm("Delete this user?")) exec("auth/user/v1/delete", {});
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
          <DetailRow label="Created">{fmtTime(data.create_at)}</DetailRow>
          <DetailRow label="Modified">{fmtTime(data.modify_at)}</DetailRow>
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
                await exec("admin/user/changepassword", {
                  password: newPass,
                });
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
          {Object.keys(data.roles ?? {}).length > 0 ? (
            <Table headers={["Role ID", "Assigned", ""]}>
              {Object.values(data.roles).map((r) => (
                <tr key={r.role_id}>
                  <Td>{r.role_id}</Td>
                  <Td>{fmtTime(r.assigned_at)}</Td>
                  <Td>
                    <Btn
                      variant="danger"
                      disabled={busy}
                      onClick={() => exec("auth/user/v1/revokerole", { role_id: r.role_id })}
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
            <input
              placeholder="Role ID"
              value={roleId}
              onChange={(e) => setRoleId(e.target.value)}
              className="border border-zinc-300 rounded px-3 py-1.5 text-sm flex-1"
            />
            <Btn
              disabled={busy || !roleId}
              onClick={() => {
                exec("auth/user/v1/assignrole", { grant: { role_id: roleId, assigned_at: Math.floor(Date.now() / 1000) } });
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
