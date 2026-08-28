import type { LureEffectiveness } from "../../types/analysis";

function pct(value: number): string {
  return `${Math.round(value * 1000) / 10}%`;
}

interface LureEffectivenessTableProps {
  lures: LureEffectiveness[];
}

export default function LureEffectivenessTable({ lures }: LureEffectivenessTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Most Effective Lures</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-6 py-3 font-medium">#</th>
              <th className="px-6 py-3 font-medium">Template</th>
              <th className="px-6 py-3 font-medium">Sent</th>
              <th className="px-6 py-3 font-medium">Click rate</th>
              <th className="px-6 py-3 font-medium">Submit rate</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {lures.map((lure, index) => (
              <tr key={lure.template_id}>
                <td className="px-6 py-3 text-slate-500">{index + 1}</td>
                <td className="px-6 py-3 font-medium text-slate-800">{lure.template_name}</td>
                <td className="px-6 py-3 text-slate-600">{lure.sent_count}</td>
                <td className="px-6 py-3 text-slate-600">{pct(lure.click_rate)}</td>
                <td className="px-6 py-3 text-slate-600">{pct(lure.submit_rate)}</td>
              </tr>
            ))}
            {lures.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
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
