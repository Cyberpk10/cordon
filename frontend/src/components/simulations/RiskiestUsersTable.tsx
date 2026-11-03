import type { RiskiestUser } from "../../types/analysis";
import { RiskScoreBadge } from "./SimulationStatusBadge";
import {
  Card,
  CardHeader,
  EmptyState,
  TBody,
  TD,
  TH,
  THead,
  Table,
  TableContainer,
  TableMessageRow,
} from "../ui";

interface RiskiestUsersTableProps {
  users: RiskiestUser[];
}

export default function RiskiestUsersTable({ users }: RiskiestUsersTableProps) {
  return (
    <Card padding="none" as="div">
      <CardHeader title="Riskiest Users" />
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Email</TH>
              <TH density="comfortable">Department</TH>
              <TH density="comfortable">Risk score</TH>
              <TH density="comfortable">Clicks</TH>
              <TH density="comfortable">Submits</TH>
              <TH density="comfortable">Reports</TH>
              <TH density="comfortable">Last failure</TH>
            </tr>
          </THead>
          <TBody>
            {users.map((user) => (
              <tr key={user.email}>
                <TD density="comfortable" className="text-fg">{user.email}</TD>
                <TD density="comfortable" className="text-fg-secondary">{user.department}</TD>
                <TD density="comfortable">
                  <RiskScoreBadge score={user.risk_score} />
                </TD>
                <TD density="comfortable" className="text-fg-secondary">{user.click_count}</TD>
                <TD density="comfortable" className="text-fg-secondary">{user.submit_count}</TD>
                <TD density="comfortable" className="text-fg-secondary">{user.report_count}</TD>
                <TD density="comfortable" className="text-fg-secondary">
                  {user.last_failure_at ? new Date(user.last_failure_at).toLocaleDateString() : "—"}
                </TD>
              </tr>
            ))}
            {users.length === 0 && (
              <TableMessageRow colSpan={7}>
                <EmptyState variant="inline" title="No campaign activity in this period." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
