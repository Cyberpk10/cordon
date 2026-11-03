import { useEffect, useState } from "react";
import { downloadAuditReport, listAuditReports } from "../../api/client";
import type { AuditReportSummary } from "../../types/analysis";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  TBody,
  TD,
  TH,
  THead,
  Table,
  TableContainer,
  TableMessageRow,
} from "../ui";

interface RecentReportsListProps {
  refreshToken: number;
}

export default function RecentReportsList({ refreshToken }: RecentReportsListProps) {
  const [reports, setReports] = useState<AuditReportSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    listAuditReports({ pageSize: 10 })
      .then((data) => {
        if (!cancelled) setReports(data.items);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load reports.");
      });

    return () => {
      cancelled = true;
    };
  }, [refreshToken]);

  return (
    <Card padding="none" as="div">
      <CardHeader title="Recent Evidence Packs" />
      {error && <ErrorState message={error} className="m-4" />}
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Generated</TH>
              <TH density="comfortable">Framework</TH>
              <TH density="comfortable">Period</TH>
              <TH density="comfortable">Coverage</TH>
              <TH density="comfortable">Download</TH>
            </tr>
          </THead>
          <TBody>
            {reports.map((report) => (
              <tr key={report.id}>
                <TD density="comfortable" className="text-fg-secondary">{new Date(report.created_at).toLocaleString()}</TD>
                <TD density="comfortable" className="text-fg">{report.framework_name}</TD>
                <TD density="comfortable" className="text-fg-secondary">
                  {new Date(report.period_start).toLocaleDateString()} –{" "}
                  {new Date(report.period_end).toLocaleDateString()}
                </TD>
                <TD density="comfortable" className="text-fg-secondary">
                  {report.operating_controls}/{report.total_controls} controls
                </TD>
                <TD density="comfortable">
                  <div className="flex gap-3">
                    <Button variant="link" onClick={() => downloadAuditReport(report.id, "pdf")}>
                      PDF
                    </Button>
                    <Button variant="link" onClick={() => downloadAuditReport(report.id, "json")}>
                      JSON
                    </Button>
                  </div>
                </TD>
              </tr>
            ))}
            {!error && reports.length === 0 && (
              <TableMessageRow colSpan={5}>
                <EmptyState variant="inline" title="No evidence packs generated yet." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
