import type { RiskiestUser } from "../../types/analysis";
import { RiskScoreBadge } from "./SimulationStatusBadge";

interface RiskiestUsersTableProps {
  users: RiskiestUser[];
}

export default function RiskiestUsersTable({ users }: RiskiestUsersTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Riskiest Users</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-6 py-3 font-medium">Email</th>
              <th className="px-6 py-3 font-medium">Department</th>
              <th className="px-6 py-3 font-medium">Risk score</th>
              <th className="px-6 py-3 font-medium">Clicks</th>
              <th className="px-6 py-3 font-medium">Submits</th>
              <th className="px-6 py-3 font-medium">Reports</th>
              <th className="px-6 py-3 font-medium">Last failure</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {users.map((user) => (
              <tr key={user.email}>
                <td className="px-6 py-3 text-slate-800">{user.email}</td>
                <td className="px-6 py-3 text-slate-600">{user.department}</td>
                <td className="px-6 py-3">
                  <RiskScoreBadge score={user.risk_score} />
                </td>
                <td className="px-6 py-3 text-slate-600">{user.click_count}</td>
                <td className="px-6 py-3 text-slate-600">{user.submit_count}</td>
                <td className="px-6 py-3 text-slate-600">{user.report_count}</td>
                <td className="px-6 py-3 text-slate-500">
                  {user.last_failure_at ? new Date(user.last_failure_at).toLocaleDateString() : "—"}
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-8 text-center text-slate-500">
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
