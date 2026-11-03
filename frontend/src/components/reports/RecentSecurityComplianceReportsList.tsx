import { useEffect, useState } from "react";
import { downloadSecurityComplianceReport, listSecurityComplianceReports } from "../../api/client";
import type { SecurityComplianceReportSummary } from "../../types/analysis";
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

interface RecentSecurityComplianceReportsListProps {
  refreshToken: number;
  onView: (id: string) => void;
}

export default function RecentSecurityComplianceReportsList({
  refreshToken,
  onView,
}: RecentSecurityComplianceReportsListProps) {
  const [reports, setReports] = useState<SecurityComplianceReportSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    listSecurityComplianceReports({ pageSize: 10 })
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
      <CardHeader title="Recent Reports" />
      {error && <ErrorState message={error} className="m-4" />}
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Generated</TH>
              <TH density="comfortable">Period</TH>
              <TH density="comfortable">Threats Detected</TH>
              <TH density="comfortable">Exposure Avoided</TH>
              <TH density="comfortable">View / Download</TH>
            </tr>
          </THead>
          <TBody>
            {reports.map((report) => (
              <tr key={report.id}>
                <TD density="comfortable" className="text-fg-secondary">{new Date(report.created_at).toLocaleString()}</TD>
                <TD density="comfortable" className="text-fg-secondary">
                  {new Date(report.period_start).toLocaleDateString()} –{" "}
                  {new Date(report.period_end).toLocaleDateString()}
                </TD>
                <TD density="comfortable" className="text-fg-secondary">{report.threats_detected}</TD>
                <TD density="comfortable" className="text-fg-secondary">
                  ${report.exposure_avoided_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}
                </TD>
                <TD density="comfortable">
                  <div className="flex gap-3">
                    <Button variant="link" onClick={() => onView(report.id)}>
                      View
                    </Button>
                    <Button
                      variant="link"
                      onClick={() => downloadSecurityComplianceReport(report.id, "pdf")}
                    >
                      PDF
                    </Button>
                  </div>
                </TD>
              </tr>
            ))}
            {!error && reports.length === 0 && (
              <TableMessageRow colSpan={5}>
                <EmptyState variant="inline" title="No reports generated yet." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
