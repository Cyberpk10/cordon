import type { LureEffectiveness } from "../../types/analysis";
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

function pct(value: number): string {
  return `${Math.round(value * 1000) / 10}%`;
}

interface LureEffectivenessTableProps {
  lures: LureEffectiveness[];
}

export default function LureEffectivenessTable({ lures }: LureEffectivenessTableProps) {
  return (
    <Card padding="none" as="div">
      <CardHeader title="Most Effective Lures" />
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">#</TH>
              <TH density="comfortable">Template</TH>
              <TH density="comfortable">Sent</TH>
              <TH density="comfortable">Click rate</TH>
              <TH density="comfortable">Submit rate</TH>
            </tr>
          </THead>
          <TBody>
            {lures.map((lure, index) => (
              <tr key={lure.template_id}>
                <TD density="comfortable" className="text-fg-secondary">{index + 1}</TD>
                <TD density="comfortable" className="font-semibold text-fg">{lure.template_name}</TD>
                <TD density="comfortable" className="text-fg-secondary">{lure.sent_count}</TD>
                <TD density="comfortable" className="text-fg-secondary">{pct(lure.click_rate)}</TD>
                <TD density="comfortable" className="text-fg-secondary">{pct(lure.submit_rate)}</TD>
              </tr>
            ))}
            {lures.length === 0 && (
              <TableMessageRow colSpan={5}>
                <EmptyState variant="inline" title="No campaigns sent in this period." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
