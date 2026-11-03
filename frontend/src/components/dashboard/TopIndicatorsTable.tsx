import type { Severity, TopIndicator } from "../../types/analysis";
import {
  Badge,
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
  type BadgeTone,
} from "../ui";

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  low: "neutral",
  medium: "warning",
  high: "danger",
};

interface TopIndicatorsTableProps {
  indicators: TopIndicator[];
}

export default function TopIndicatorsTable({ indicators }: TopIndicatorsTableProps) {
  return (
    <Card padding="none" as="div">
      <CardHeader title="Top Threat Indicators" />
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">#</TH>
              <TH density="comfortable">Indicator</TH>
              <TH density="comfortable">Category</TH>
              <TH density="comfortable">Severity</TH>
              <TH density="comfortable">Count</TH>
            </tr>
          </THead>
          <TBody>
            {indicators.map((indicator, index) => (
              <tr key={indicator.indicator_id}>
                <TD density="comfortable" className="text-fg-secondary">{index + 1}</TD>
                <TD density="comfortable" className="font-semibold text-fg">{indicator.title}</TD>
                <TD density="comfortable" className="text-fg-secondary">{indicator.category}</TD>
                <TD density="comfortable">
                  <Badge tone={SEVERITY_TONE[indicator.severity]} caps>
                    {indicator.severity}
                  </Badge>
                </TD>
                <TD density="comfortable" className="text-fg-secondary">{indicator.count}</TD>
              </tr>
            ))}
            {indicators.length === 0 && (
              <TableMessageRow colSpan={5}>
                <EmptyState variant="inline" title="No indicators triggered in this period." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
