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
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Recent Reports</h3>
      </div>
      {error && <div className="p-4 text-sm text-red-700">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-6 py-3 font-medium">Generated</th>
            <th className="px-6 py-3 font-medium">Period</th>
            <th className="px-6 py-3 font-medium">Threats Detected</th>
            <th className="px-6 py-3 font-medium">Exposure Avoided</th>
            <th className="px-6 py-3 font-medium">View / Download</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {reports.map((report) => (
            <tr key={report.id}>
              <td className="px-6 py-3 text-slate-600">{new Date(report.created_at).toLocaleString()}</td>
              <td className="px-6 py-3 text-slate-600">
                {new Date(report.period_start).toLocaleDateString()} –{" "}
                {new Date(report.period_end).toLocaleDateString()}
              </td>
              <td className="px-6 py-3 text-slate-600">{report.threats_detected}</td>
              <td className="px-6 py-3 text-slate-600">
                ${report.exposure_avoided_usd.toLocaleString(undefined, { maximumFractionDigits: 0 })}
              </td>
              <td className="px-6 py-3">
                <div className="flex gap-3">
                  <button
                    onClick={() => onView(report.id)}
                    className="font-medium text-indigo-600 hover:text-indigo-500"
                  >
                    View
                  </button>
                  <button
                    onClick={() => downloadSecurityComplianceReport(report.id, "pdf")}
                    className="font-medium text-indigo-600 hover:text-indigo-500"
                  >
                    PDF
                  </button>
                </div>
              </td>
            </tr>
          ))}
          {reports.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                No reports generated yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
