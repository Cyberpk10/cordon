import { useEffect, useState } from "react";
import { downloadSecurityComplianceReport, listSecurityComplianceReports } from "../../api/client";
import type { SecurityComplianceReportSummary } from "../../types/analysis";

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
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Recent Reports</h3>
      </div>
      {error && <div className="p-4 text-sm text-danger">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
          <tr>
            <th className="px-6 py-3 font-semibold">Generated</th>
            <th className="px-6 py-3 font-semibold">Period</th>
            <th className="px-6 py-3 font-semibold">Threats Detected</th>
            <th className="px-6 py-3 font-semibold">Exposure Avoided</th>
            <th className="px-6 py-3 font-semibold">View / Download</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {reports.map((report) => (
            <tr key={report.id}>
              <td className="px-6 py-3 text-fg-secondary">{new Date(report.created_at).toLocaleString()}</td>
              <td className="px-6 py-3 text-fg-secondary">
                {new Date(report.period_start).toLocaleDateString()} –{" "}
                {new Date(report.period_end).toLocaleDateString()}
              </td>
              <td className="px-6 py-3 text-fg-secondary">{report.threats_detected}</td>
              <td className="px-6 py-3 text-fg-secondary">
                ${report.exposure_avoided_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}
              </td>
              <td className="px-6 py-3">
                <div className="flex gap-3">
                  <button
                    onClick={() => onView(report.id)}
                    className="font-semibold text-accent hover:text-accent-hover"
                  >
                    View
                  </button>
                  <button
                    onClick={() => downloadSecurityComplianceReport(report.id, "pdf")}
                    className="font-semibold text-accent hover:text-accent-hover"
                  >
                    PDF
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {reports.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-fg-secondary">
                No reports generated yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
