import { useState } from "react";
import { useParams } from "react-router-dom";
import { getRole, post } from "../api";
import { useAuth } from "../auth";
import { useAsync, fmtTime, stateName, roleStates } from "../hooks";
import { PageHeader, Btn, Badge, Card, DetailRow, Table, Td, Loading, ErrorBox } from "../ui";

export default function RoleDetail() {
  const { id } = useParams<{ id: string }>();
  const { user: me } = useAuth();
  const { data, error, loading, reload } = useAsync(() => getRole(id!), [id]);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [funcName, setFuncName] = useState("");
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

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

  return (
    <>
      <PageHeader
        title={data.name || data.id}
        action={
          data.state === 1 ? (
            <Btn
              variant="danger"
              disabled={busy}
              onClick={() => {
                if (confirm("Delete this role?")) exec("auth/role/v1/delete", {});
              }}
            >
              Delete
            </Btn>
          ) : undefined
        }
      />
      {actionErr && <ErrorBox message={actionErr} />}

      <Card>
        <div className="p-4">
          <DetailRow label="ID">{data.id}</DetailRow>
          <DetailRow label="Name">{data.name}</DetailRow>
          <DetailRow label="Description">{data.description || "-"}</DetailRow>
          <DetailRow label="State">
            <Badge color={data.state === 1 ? "green" : "red"}>
              {stateName(data.state, roleStates)}
            </Badge>
          </DetailRow>
          <DetailRow label="Created">{fmtTime(data.create_at)}</DetailRow>
          <DetailRow label="Modified">{fmtTime(data.modify_at)}</DetailRow>
        </div>
      </Card>

      <Card>
        <div className="p-4">
          <h2 className="text-sm font-semibold text-zinc-900 mb-3">Rename / Description</h2>
          <div className="flex gap-2 mb-2">
            <input
              placeholder="New name"
              value={newName}
              onChange={(e) => setNewName(e.target.value)}
              className="border border-zinc-300 rounded px-3 py-1.5 text-sm flex-1"
            />
            <Btn disabled={busy || !newName} onClick={() => { exec("auth/role/v1/rename", { name: newName }); setNewName(""); }}>
              Rename
            </Btn>
          </div>
          <div className="flex gap-2">
            <input
              placeholder="New description"
              value={newDesc}
              onChange={(e) => setNewDesc(e.target.value)}
              className="border border-zinc-300 rounded px-3 py-1.5 text-sm flex-1"
            />
            <Btn disabled={busy || !newDesc} onClick={() => { exec("auth/role/v1/setdescription", { description: newDesc }); setNewDesc(""); }}>
              Set
            </Btn>
          </div>
        </div>
      </Card>

      <Card>
        <div className="p-4">
          <h2 className="text-sm font-semibold text-zinc-900 mb-3">Functions</h2>
          {Object.keys(data.functions ?? {}).length > 0 ? (
            <Table headers={["Function", "Granted", ""]}>
              {Object.values(data.functions).map((f) => (
                <tr key={f.function}>
                  <Td>
                    <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{f.function}</code>
                  </Td>
                  <Td>{fmtTime(f.granted_at)}</Td>
                  <Td>
                    <Btn
                      variant="danger"
                      disabled={busy}
                      onClick={() => exec("auth/role/v1/removefunction", { function: f.function })}
                    >
                      Remove
                    </Btn>
                  </Td>
                </tr>
              ))}
            </Table>
          ) : (
            <p className="text-sm text-zinc-400">No functions granted.</p>
          )}
          <div className="flex gap-2 mt-3">
            <input
              placeholder="Function name (e.g. auth.user.v1.* or *)"
              value={funcName}
              onChange={(e) => setFuncName(e.target.value)}
              className="border border-zinc-300 rounded px-3 py-1.5 text-sm flex-1"
            />
            <Btn
              disabled={busy || !funcName}
              onClick={() => {
                exec("auth/role/v1/addfunction", {
                  grant: { function: funcName, granted_at: Math.floor(Date.now() / 1000) },
                });
                setFuncName("");
              }}
            >
              Add Function
            </Btn>
          </div>
        </div>
      </Card>
    </>
  );
}
