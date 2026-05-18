import { useState } from "react";
import { useParams } from "react-router-dom";
import { roleClient } from "../clients";
import { State } from "../gen/auth/role/v1/role_pb.js";
import { useAsync, fmtTime, fmtMicroTime, stateName, roleStates } from "../hooks";
import { PageHeader, Btn, Badge, Card, DetailRow, Table, Td, Loading, ErrorBox } from "../ui";

export default function RoleDetail() {
  const { id } = useParams<{ id: string }>();
  const { data, error, loading, reload } = useAsync(() => roleClient.get(id!), [id]);
  const [busy, setBusy] = useState(false);
  const [actionErr, setActionErr] = useState<string | null>(null);
  const [funcName, setFuncName] = useState("");
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

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
        title={data.name || data.id}
        action={
          <div className="flex gap-2">
            {data.state === State.ACTIVE && (
              <Btn variant="secondary" disabled={busy} onClick={() => exec(() => roleClient.deactivate(id!))}>
                Deactivate
              </Btn>
            )}
            {data.state === State.INACTIVE && (
              <Btn disabled={busy} onClick={() => exec(() => roleClient.activate(id!))}>
                Activate
              </Btn>
            )}
          </div>
        }
      />
      {actionErr && <ErrorBox message={actionErr} />}

      <Card>
        <div className="p-4">
          <DetailRow label="ID">{data.id}</DetailRow>
          <DetailRow label="Name">{data.name}</DetailRow>
          <DetailRow label="Description">{data.description || "-"}</DetailRow>
          <DetailRow label="State">
            <Badge
              color={
                data.state === State.ACTIVE
                  ? "green"
                  : data.state === State.INACTIVE
                    ? "yellow"
                    : "red"
              }
            >
              {stateName(data.state, roleStates)}
            </Badge>
          </DetailRow>
          <DetailRow label="Created">{fmtMicroTime(data.createAt)}</DetailRow>
          <DetailRow label="Modified">{fmtMicroTime(data.modifyAt)}</DetailRow>
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
            <Btn disabled={busy || !newName} onClick={() => { exec(() => roleClient.rename(id!, newName)); setNewName(""); }}>
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
            <Btn disabled={busy || !newDesc} onClick={() => { exec(() => roleClient.setDescription(id!, newDesc)); setNewDesc(""); }}>
              Set
            </Btn>
          </div>
        </div>
      </Card>

      <Card>
        <div className="p-4">
          <h2 className="text-sm font-semibold text-zinc-900 mb-3">Functions</h2>
          {Object.keys(data.functions).length > 0 ? (
            <Table headers={["Function", "Granted", ""]}>
              {Object.values(data.functions).map((f) => (
                <tr key={f.function}>
                  <Td>
                    <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{f.function}</code>
                  </Td>
                  <Td>{fmtTime(f.grantedAt)}</Td>
                  <Td>
                    <Btn
                      variant="danger"
                      disabled={busy}
                      onClick={() => exec(() => roleClient.removeFunction(id!, f.function))}
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
                exec(() =>
                  roleClient.addFunction(id!, {
                    $typeName: "auth.role.v1.FunctionGrant",
                    function: funcName,
                    grantedAt: BigInt(Math.floor(Date.now() / 1000)),
                  }),
                );
                setFuncName("");
              }}
            >
              Add Function
            </Btn>
          </div>
        </div>
      </Card>

      {data.state !== State.DELETED && (
        <Card>
          <div className="p-4 border-l-4 border-red-400">
            <h2 className="text-sm font-semibold text-red-700 mb-2">Danger zone</h2>
            <p className="text-xs text-zinc-500 mb-3">
              Delete permanently removes this role. There is no undo — Deactivate is the reversible alternative.
            </p>
            <Btn
              variant="danger"
              disabled={busy}
              onClick={() => {
                if (confirm("Delete this role permanently? This cannot be undone.")) {
                  exec(() => roleClient.delete(id!));
                }
              }}
            >
              Delete role
            </Btn>
          </div>
        </Card>
      )}
    </>
  );
}
