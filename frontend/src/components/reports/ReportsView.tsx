import { useState } from "react";
import {
  downloadSecurityComplianceReport,
  generateSecurityComplianceReport,
  getSecurityComplianceReport,
} from "../../api/client";
import type { SecurityComplianceReportDetail } from "../../types/analysis";
import ReportPreview from "./ReportPreview";
import RecentSecurityComplianceReportsList from "./RecentSecurityComplianceReportsList";

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
      <div className="flex flex-wrap items-end justify-between gap-4 rounded-xl border border-slate-800 bg-slate-900 p-5 shadow-sm">
        <div>
          <h2 className="text-lg font-semibold text-white">Security &amp; Compliance Report</h2>
          <p className="text-sm text-slate-300">
            A board- and auditor-ready summary of real detection, containment, and compliance
            activity for a selected period.
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm text-slate-200">
            From
            <input
              type="date"
              value={dateFrom}
              onChange={(event) => setDateFrom(event.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm text-slate-200">
            To
            <input
              type="date"
              value={dateTo}
              onChange={(event) => setDateTo(event.target.value)}
              className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
            />
          </label>
          <button
            onClick={handleGenerate}
            disabled={isGenerating}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            {isGenerating ? "Generating…" : "Generate Report"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {report && (
        <ReportPreview report={report} onDownload={handleDownload} isDownloading={isDownloading} />
      )}

      <RecentSecurityComplianceReportsList refreshToken={refreshToken} onView={handleView} />
    </div>
  );
}
