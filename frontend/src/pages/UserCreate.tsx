import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { post } from "../api";
import { PageHeader, Btn, Card, ErrorBox } from "../ui";

export default function UserCreate() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const id = `user-${crypto.randomUUID()}`;
      await post("admin/user/create", { id, email, password });
      navigate(`/users/${id}`);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader title="Create User" />
      {error && <ErrorBox message={error} />}
      <Card>
        <form onSubmit={handleSubmit} className="p-4 space-y-4">
          <div>
            <label className="block text-sm font-medium text-zinc-700 mb-1">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="w-full border border-zinc-300 rounded px-3 py-1.5 text-sm"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-zinc-700 mb-1">Password</label>
            <input
              type="password"
              required
              minLength={4}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full border border-zinc-300 rounded px-3 py-1.5 text-sm"
            />
          </div>
          <Btn type="submit" disabled={busy}>
            Create User
          </Btn>
        </form>
      </Card>
    </>
  );
}
