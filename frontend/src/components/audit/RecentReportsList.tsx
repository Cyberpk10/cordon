import { useEffect, useState } from "react";
import { downloadAuditReport, listAuditReports } from "../../api/client";
import type { AuditReportSummary } from "../../types/analysis";

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
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Recent Evidence Packs</h3>
      </div>
      {error && <div className="p-4 text-sm text-danger">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
          <tr>
            <th className="px-6 py-3 font-semibold">Generated</th>
            <th className="px-6 py-3 font-semibold">Framework</th>
            <th className="px-6 py-3 font-semibold">Period</th>
            <th className="px-6 py-3 font-semibold">Coverage</th>
            <th className="px-6 py-3 font-semibold">Download</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {reports.map((report) => (
            <tr key={report.id}>
              <td className="px-6 py-3 text-fg-secondary">{new Date(report.created_at).toLocaleString()}</td>
              <td className="px-6 py-3 text-fg">{report.framework_name}</td>
              <td className="px-6 py-3 text-fg-secondary">
                {new Date(report.period_start).toLocaleDateString()} –{" "}
                {new Date(report.period_end).toLocaleDateString()}
              </td>
              <td className="px-6 py-3 text-fg-secondary">
                {report.operating_controls}/{report.total_controls} controls
              </td>
              <td className="px-6 py-3">
                <div className="flex gap-3">
                  <button
                    onClick={() => downloadAuditReport(report.id, "pdf")}
                    className="font-semibold text-accent hover:text-accent-hover"
                  >
                    PDF
                  </button>
                  <button
                    onClick={() => downloadAuditReport(report.id, "json")}
                    className="font-semibold text-accent hover:text-accent-hover"
                  >
                    JSON
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {reports.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-fg-secondary">
                No evidence packs generated yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
