import { Link } from "react-router-dom";
import { listIssuers } from "../api";
import { useAsync, fmtTime, stateName, issuerStates, issuerKinds } from "../hooks";
import { PageHeader, Table, Td, Badge, Loading, ErrorBox } from "../ui";

export default function Issuers() {
  const { data, error, loading } = useAsync(listIssuers);

  return (
    <>
      <PageHeader title="Issuers" />
      {error && <ErrorBox message={error} />}
      {loading && <Loading />}
      {data && (
        <Table headers={["Display Name", "ISS", "Kind", "State", "Created", ""]}>
          {data.map((i) => (
            <tr key={i.id} className="hover:bg-zinc-50">
              <Td>
                <Link to={`/issuers/${i.id}`} className="text-zinc-900 font-medium hover:underline">
                  {i.display_name || i.id}
                </Link>
              </Td>
              <Td>
                <code className="text-xs bg-zinc-100 px-1.5 py-0.5 rounded">{i.iss}</code>
              </Td>
              <Td>{issuerKinds[i.kind] ?? i.kind}</Td>
              <Td>
                <Badge color={i.state === 1 ? "green" : i.state === 2 ? "yellow" : "red"}>
                  {stateName(i.state, issuerStates)}
                </Badge>
              </Td>
              <Td>{fmtTime(i.create_at)}</Td>
              <Td>
                <Link to={`/issuers/${i.id}`} className="text-zinc-500 hover:text-zinc-900 text-xs">
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
