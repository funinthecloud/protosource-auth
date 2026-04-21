import { Link } from "react-router-dom";
import { listUsers } from "../api";
import { useAsync, fmtTime, stateName, userStates } from "../hooks";
import { PageHeader, LinkBtn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

function stateBadge(state: number) {
  const color = state === 1 ? "green" : state === 2 ? "yellow" : "red";
  return <Badge color={color}>{stateName(state, userStates)}</Badge>;
}

export default function Users() {
  const { data, error, loading } = useAsync(listUsers);

  return (
    <>
      <PageHeader title="Users" action={<LinkBtn to="/users/new">Create User</LinkBtn>} />
      {error && <ErrorBox message={error} />}
      {loading && <Loading />}
      {data && (
        <Table headers={["Email", "State", "Roles", "Created", ""]}>
          {data.map((u) => (
            <tr key={u.id} className="hover:bg-zinc-50">
              <Td>
                <Link to={`/users/${u.id}`} className="text-zinc-900 font-medium hover:underline">
                  {u.email}
                </Link>
              </Td>
              <Td>{stateBadge(u.state)}</Td>
              <Td>{Object.keys(u.roles ?? {}).length}</Td>
              <Td>{fmtTime(u.create_at)}</Td>
              <Td>
                <Link to={`/users/${u.id}`} className="text-zinc-500 hover:text-zinc-900 text-xs">
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
