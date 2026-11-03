import { ListX } from "lucide-react";
import type { ActivityEvent } from "../../types/analysis";
import { Card, EmptyState, TBody, TD, TH, THead, Table, TableContainer } from "../ui";

interface EvidenceEventsTableProps {
  events: ActivityEvent[];
}

export default function EvidenceEventsTable({ events }: EvidenceEventsTableProps) {
  if (events.length === 0) {
    return (
      <div className="rounded-card border border-line bg-surface-card">
        <EmptyState variant="inline" icon={ListX} title="No evidence events recorded." />
      </div>
    );
  }

  return (
    <Card padding="none" as="div" className="overflow-x-auto">
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH>Time</TH>
              <TH>Action</TH>
              <TH>Source IP</TH>
              <TH>Target</TH>
              <TH>Bytes</TH>
              <TH>Outcome</TH>
            </tr>
          </THead>
          <TBody>
            {events.map((event) => (
              <tr key={event.id ?? event.timestamp}>
                <TD className="text-fg-secondary">
                  {new Date(event.timestamp).toLocaleString()}
                </TD>
                <TD className="text-fg">{event.action}</TD>
                <TD className="text-fg-secondary">{event.source_ip ?? "—"}</TD>
                <TD className="text-fg-secondary">{event.target ?? "—"}</TD>
                <TD className="text-fg-secondary">
                  {event.bytes !== null ? event.bytes.toLocaleString() : "—"}
                </TD>
                <TD className="text-fg-secondary">{event.outcome ?? "—"}</TD>
              </tr>
            ))}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
