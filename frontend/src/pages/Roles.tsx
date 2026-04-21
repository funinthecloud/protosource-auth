import { Link } from "react-router-dom";
import { listRoles } from "../api";
import { useAsync, fmtTime, stateName, roleStates } from "../hooks";
import { PageHeader, LinkBtn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

export default function Roles() {
  const { data, error, loading } = useAsync(listRoles);

  return (
    <>
      <PageHeader title="Roles" action={<LinkBtn to="/roles/new">Create Role</LinkBtn>} />
      {error && <ErrorBox message={error} />}
      {loading && <Loading />}
      {data && (
        <Table headers={["Name", "State", "Functions", "Created", ""]}>
          {data.map((r) => (
            <tr key={r.id} className="hover:bg-zinc-50">
              <Td>
                <Link to={`/roles/${r.id}`} className="text-zinc-900 font-medium hover:underline">
                  {r.name || r.id}
                </Link>
              </Td>
              <Td>
                <Badge color={r.state === 1 ? "green" : "red"}>
                  {stateName(r.state, roleStates)}
                </Badge>
              </Td>
              <Td>{Object.keys(r.functions ?? {}).length}</Td>
              <Td>{fmtTime(r.create_at)}</Td>
              <Td>
                <Link to={`/roles/${r.id}`} className="text-zinc-500 hover:text-zinc-900 text-xs">
                  View
                </Link>
              </Td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}
