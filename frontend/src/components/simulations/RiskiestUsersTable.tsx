import type { RiskiestUser } from "../../types/analysis";
import { RiskScoreBadge } from "./SimulationStatusBadge";

interface RiskiestUsersTableProps {
  users: RiskiestUser[];
}

export default function RiskiestUsersTable({ users }: RiskiestUsersTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Riskiest Users</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
            <tr>
              <th className="px-6 py-3 font-semibold">Email</th>
              <th className="px-6 py-3 font-semibold">Department</th>
              <th className="px-6 py-3 font-semibold">Risk score</th>
              <th className="px-6 py-3 font-semibold">Clicks</th>
              <th className="px-6 py-3 font-semibold">Submits</th>
              <th className="px-6 py-3 font-semibold">Reports</th>
              <th className="px-6 py-3 font-semibold">Last failure</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {users.map((user) => (
              <tr key={user.email}>
                <td className="px-6 py-3 text-fg">{user.email}</td>
                <td className="px-6 py-3 text-fg-secondary">{user.department}</td>
                <td className="px-6 py-3">
                  <RiskScoreBadge score={user.risk_score} />
                </td>
                <td className="px-6 py-3 text-fg-secondary">{user.click_count}</td>
                <td className="px-6 py-3 text-fg-secondary">{user.submit_count}</td>
                <td className="px-6 py-3 text-fg-secondary">{user.report_count}</td>
                <td className="px-6 py-3 text-fg-secondary">
                  {user.last_failure_at ? new Date(user.last_failure_at).toLocaleDateString() : "—"}
                </td>
              </tr>
            ))}
            {users.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-8 text-center text-fg-secondary">
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
