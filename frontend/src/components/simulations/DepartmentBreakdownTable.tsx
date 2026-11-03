import type { DepartmentBreakdown } from "../../types/analysis";
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

interface DepartmentBreakdownTableProps {
  departments: DepartmentBreakdown[];
}

export default function DepartmentBreakdownTable({ departments }: DepartmentBreakdownTableProps) {
  return (
    <Card padding="none" as="div">
      <CardHeader title="Department Breakdown" />
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Department</TH>
              <TH density="comfortable">Employees tested</TH>
              <TH density="comfortable">Clicks</TH>
              <TH density="comfortable">Submits</TH>
              <TH density="comfortable">Reports</TH>
              <TH density="comfortable">Avg. risk score</TH>
            </tr>
          </THead>
          <TBody>
            {departments.map((dept) => (
              <tr key={dept.department}>
                <TD density="comfortable" className="font-semibold text-fg">{dept.department}</TD>
                <TD density="comfortable" className="text-fg-secondary">{dept.employees_tested}</TD>
                <TD density="comfortable" className="text-fg-secondary">{dept.click_count}</TD>
                <TD density="comfortable" className="text-fg-secondary">{dept.submit_count}</TD>
                <TD density="comfortable" className="text-fg-secondary">{dept.report_count}</TD>
                <TD density="comfortable">
                  <RiskScoreBadge score={Math.round(dept.avg_risk_score)} />
                </TD>
              </tr>
            ))}
            {departments.length === 0 && (
              <TableMessageRow colSpan={6}>
                <EmptyState variant="inline" title="No campaign activity in this period." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
