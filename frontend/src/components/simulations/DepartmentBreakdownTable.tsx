import type { DepartmentBreakdown } from "../../types/analysis";
import { RiskScoreBadge } from "./SimulationStatusBadge";

interface DepartmentBreakdownTableProps {
  departments: DepartmentBreakdown[];
}

export default function DepartmentBreakdownTable({ departments }: DepartmentBreakdownTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Department Breakdown</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-6 py-3 font-medium">Department</th>
              <th className="px-6 py-3 font-medium">Employees tested</th>
              <th className="px-6 py-3 font-medium">Clicks</th>
              <th className="px-6 py-3 font-medium">Submits</th>
              <th className="px-6 py-3 font-medium">Reports</th>
              <th className="px-6 py-3 font-medium">Avg. risk score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {departments.map((dept) => (
              <tr key={dept.department}>
                <td className="px-6 py-3 font-medium text-slate-800">{dept.department}</td>
                <td className="px-6 py-3 text-slate-600">{dept.employees_tested}</td>
                <td className="px-6 py-3 text-slate-600">{dept.click_count}</td>
                <td className="px-6 py-3 text-slate-600">{dept.submit_count}</td>
                <td className="px-6 py-3 text-slate-600">{dept.report_count}</td>
                <td className="px-6 py-3">
                  <RiskScoreBadge score={Math.round(dept.avg_risk_score)} />
                </td>
              </tr>
            ))}
            {departments.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-slate-500">
                  No campaign activity in this period.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
