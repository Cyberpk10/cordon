import type { AuditControlEvidence } from "../../types/analysis";
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
} from "../ui";

interface EvidenceTableProps {
  controls: AuditControlEvidence[];
}

export default function EvidenceTable({ controls }: EvidenceTableProps) {
  return (
    <Card padding="none" as="div">
      <CardHeader title="Per-Control Evidence" />
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Control</TH>
              <TH density="comfortable">Name</TH>
              <TH density="comfortable">Detections</TH>
              <TH density="comfortable">Status</TH>
              <TH density="comfortable">Sample Cases</TH>
            </tr>
          </THead>
          <TBody>
            {controls.map((control) => (
              <tr key={control.control_id}>
                <TD density="comfortable" className="font-mono text-xs text-fg">{control.control_id}</TD>
                <TD density="comfortable" className="text-fg">{control.control_name}</TD>
                <TD density="comfortable" className="text-fg-secondary">{control.detection_count}</TD>
                <TD density="comfortable">
                  <Badge tone={control.operating ? "success" : "neutral"}>
                    {control.operating ? "Operating" : "No evidence"}
                  </Badge>
                </TD>
                <TD density="comfortable">
                  <div className="flex flex-wrap gap-1">
                    {control.sample_cases.length === 0 && (
                      <span className="text-xs text-fg-muted">—</span>
                    )}
                    {control.sample_cases.map((sample) => (
                      <Badge key={sample.id} size="sm" title={new Date(sample.created_at).toLocaleString()}>
                        {sample.id.slice(0, 8)} · {sample.verdict}
                      </Badge>
                    ))}
                  </div>
                </TD>
              </tr>
            ))}
            {controls.length === 0 && (
              <TableMessageRow colSpan={5}>
                <EmptyState variant="inline" title="No controls found for this framework." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
