import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { roleClient } from "../clients";
import { PageHeader, Btn, Card, ErrorBox } from "../ui";

export default function RoleCreate() {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const id = `role-${crypto.randomUUID()}`;
      await roleClient.create(id, name, description);
      navigate(`/roles/${id}`);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Create Role" />
      {error && <ErrorBox message={error} />}
      <Card>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-zinc-700 mb-1">Name</label>
            <input
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full border border-zinc-300 rounded px-3 py-1.5 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-zinc-700 mb-1">Description</label>
            <input
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full border border-zinc-300 rounded px-3 py-1.5 text-sm"
            />
          </div>
          <Btn type="submit" disabled={busy}>
            Create Role
          </Btn>
        </form>
      </Card>
    </>
  );
}
