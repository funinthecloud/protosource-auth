import { Link } from "react-router-dom";
import { userClient } from "../clients";
import { State } from "../gen/auth/user/v1/user_pb.js";
import { useAsync, fmtMicroTime, stateName, userStates } from "../hooks";
import { PageHeader, LinkBtn, Table, Td, Badge, Loading, ErrorBox } from "../ui";

function stateBadge(state: State) {
  const color = state === State.ACTIVE ? "green" : state === State.LOCKED ? "yellow" : "red";
  return <Badge color={color}>{stateName(state, userStates)}</Badge>;
}

export default function Users() {
  const { data, error, loading } = useAsync(() => userClient.queryByState(State.ACTIVE));

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
              <Td>{Object.keys(u.roles).length}</Td>
              <Td>{fmtMicroTime(u.createAt)}</Td>
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
