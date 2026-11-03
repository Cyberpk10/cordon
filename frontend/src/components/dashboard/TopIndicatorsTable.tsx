import type { Severity, TopIndicator } from "../../types/analysis";

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "bg-surface-raised text-fg border-line-strong",
  medium: "bg-warning/10 text-warning border-warning/35",
  high: "bg-danger/10 text-danger border-danger/35",
};

interface TopIndicatorsTableProps {
  indicators: TopIndicator[];
}

export default function TopIndicatorsTable({ indicators }: TopIndicatorsTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Top Threat Indicators</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
            <tr>
              <th className="px-6 py-3 font-semibold">#</th>
              <th className="px-6 py-3 font-semibold">Indicator</th>
              <th className="px-6 py-3 font-semibold">Category</th>
              <th className="px-6 py-3 font-semibold">Severity</th>
              <th className="px-6 py-3 font-semibold">Count</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {indicators.map((indicator, index) => (
              <tr key={indicator.indicator_id}>
                <td className="px-6 py-3 text-fg-secondary">{index + 1}</td>
                <td className="px-6 py-3 font-semibold text-fg">{indicator.title}</td>
                <td className="px-6 py-3 text-fg-secondary">{indicator.category}</td>
                <td className="px-6 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[indicator.severity]}`}
                  >
                    {indicator.severity}
                  </span>
                </td>
                <td className="px-6 py-3 text-fg-secondary">{indicator.count}</td>
              </tr>
            ))}
            {indicators.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-fg-secondary">
                  No indicators triggered in this period.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
