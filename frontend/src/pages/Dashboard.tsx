import { Link } from "react-router-dom";
import { listUsers, listRoles, listIssuers, listKeys, listTokens } from "../api";
import { useAsync } from "../hooks";
import { PageHeader, Loading, ErrorBox } from "../ui";

function CountCard({ label, to, count, loading }: { label: string; to: string; count: number; loading: boolean }) {
  return (
    <Link
      to={to}
      className="bg-white rounded-lg border border-zinc-200 p-6 hover:border-zinc-400 transition-colors"
    >
      <div className="text-sm text-zinc-500">{label}</div>
      <div className="text-3xl font-semibold text-zinc-900 mt-1">
        {loading ? "-" : count}
      </div>
    </Link>
  );
}

export default function Dashboard() {
  const users = useAsync(listUsers);
  const roles = useAsync(listRoles);
  const issuers = useAsync(listIssuers);
  const keys = useAsync(listKeys);
  const tokens = useAsync(listTokens);

  const anyError = users.error || roles.error || issuers.error || keys.error || tokens.error;

  return (
    <>
      <PageHeader title="Dashboard" />
      {anyError && <ErrorBox message={anyError} />}
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4 p-6">
        <CountCard label="Active Users" to="/users" count={users.data?.length ?? 0} loading={users.loading} />
        <CountCard label="Active Roles" to="/roles" count={roles.data?.length ?? 0} loading={roles.loading} />
        <CountCard label="Issuers" to="/issuers" count={issuers.data?.length ?? 0} loading={issuers.loading} />
        <CountCard label="Signing Keys" to="/keys" count={keys.data?.length ?? 0} loading={keys.loading} />
        <CountCard label="Active Tokens" to="/tokens" count={tokens.data?.length ?? 0} loading={tokens.loading} />
      </div>
      {(users.loading || roles.loading || issuers.loading || keys.loading || tokens.loading) && <Loading />}
    </>
  );
}
