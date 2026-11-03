import { useState } from "react";
import { FilePlus2 } from "lucide-react";
import {
  downloadSecurityComplianceReport,
  generateSecurityComplianceReport,
  getSecurityComplianceReport,
} from "../../api/client";
import type { SecurityComplianceReportDetail } from "../../types/analysis";
import ReportPreview from "./ReportPreview";
import RecentSecurityComplianceReportsList from "./RecentSecurityComplianceReportsList";
import { Button, DateRangeFilter, ErrorState } from "../ui";
import PageActions from "../shell/PageActions";

export default function ReportsView() {
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [report, setReport] = useState<SecurityComplianceReportDetail | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [refreshToken, setRefreshToken] = useState(0);

  const periodParams = {
    dateFrom: dateFrom ? `${dateFrom}T00:00:00` : undefined,
    dateTo: dateTo ? `${dateTo}T23:59:59` : undefined,
  };

  const handleGenerate = async () => {
    setIsGenerating(true);
    setError(null);
    try {
      const generated = await generateSecurityComplianceReport(periodParams);
      setReport(generated);
      setRefreshToken((token) => token + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to generate report.");
    } finally {
      setIsGenerating(false);
    }
  };

  const handleView = async (id: string) => {
    setError(null);
    try {
      const detail = await getSecurityComplianceReport(id);
      setReport(detail);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load report.");
    }
  };

  const handleDownload = async (format: "pdf" | "json") => {
    if (!report) return;
    setIsDownloading(true);
    try {
      await downloadSecurityComplianceReport(report.id, format);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to download report.");
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <PageActions>
        <DateRangeFilter
          label="Report period"
          from={dateFrom}
          to={dateTo}
          onFromChange={setDateFrom}
          onToChange={setDateTo}
        />
        <Button
          variant="primary"
          size="sm"
          icon={FilePlus2}
          onClick={handleGenerate}
          loading={isGenerating}
          loadingText="Generating…"
        >
          Generate Report
        </Button>
      </PageActions>

      {error && <ErrorState message={error} />}

      {report && (
        <ReportPreview report={report} onDownload={handleDownload} isDownloading={isDownloading} />
      )}

      <RecentSecurityComplianceReportsList refreshToken={refreshToken} onView={handleView} />
    </div>
  );
}
