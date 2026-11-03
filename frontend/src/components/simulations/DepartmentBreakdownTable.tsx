import type { DepartmentBreakdown } from "../../types/analysis";
import { RiskScoreBadge } from "./SimulationStatusBadge";

interface DepartmentBreakdownTableProps {
  departments: DepartmentBreakdown[];
}

export default function DepartmentBreakdownTable({ departments }: DepartmentBreakdownTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Department Breakdown</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
            <tr>
              <th className="px-6 py-3 font-semibold">Department</th>
              <th className="px-6 py-3 font-semibold">Employees tested</th>
              <th className="px-6 py-3 font-semibold">Clicks</th>
              <th className="px-6 py-3 font-semibold">Submits</th>
              <th className="px-6 py-3 font-semibold">Reports</th>
              <th className="px-6 py-3 font-semibold">Avg. risk score</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {departments.map((dept) => (
              <tr key={dept.department}>
                <td className="px-6 py-3 font-semibold text-fg">{dept.department}</td>
                <td className="px-6 py-3 text-fg-secondary">{dept.employees_tested}</td>
                <td className="px-6 py-3 text-fg-secondary">{dept.click_count}</td>
                <td className="px-6 py-3 text-fg-secondary">{dept.submit_count}</td>
                <td className="px-6 py-3 text-fg-secondary">{dept.report_count}</td>
                <td className="px-6 py-3">
                  <RiskScoreBadge score={Math.round(dept.avg_risk_score)} />
                </td>
              </tr>
            ))}
            {departments.length === 0 && (
              <tr>
                <td colSpan={6} className="px-6 py-8 text-center text-fg-secondary">
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
