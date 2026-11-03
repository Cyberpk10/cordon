import type { LureEffectiveness } from "../../types/analysis";

function pct(value: number): string {
  return `${Math.round(value * 1000) / 10}%`;
}

interface LureEffectivenessTableProps {
  lures: LureEffectiveness[];
}

export default function LureEffectivenessTable({ lures }: LureEffectivenessTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Most Effective Lures</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
            <tr>
              <th className="px-6 py-3 font-semibold">#</th>
              <th className="px-6 py-3 font-semibold">Template</th>
              <th className="px-6 py-3 font-semibold">Sent</th>
              <th className="px-6 py-3 font-semibold">Click rate</th>
              <th className="px-6 py-3 font-semibold">Submit rate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {lures.map((lure, index) => (
              <tr key={lure.template_id}>
                <td className="px-6 py-3 text-fg-secondary">{index + 1}</td>
                <td className="px-6 py-3 font-semibold text-fg">{lure.template_name}</td>
                <td className="px-6 py-3 text-fg-secondary">{lure.sent_count}</td>
                <td className="px-6 py-3 text-fg-secondary">{pct(lure.click_rate)}</td>
                <td className="px-6 py-3 text-fg-secondary">{pct(lure.submit_rate)}</td>
              </tr>
            ))}
            {lures.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-fg-secondary">
                  No campaigns sent in this period.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
