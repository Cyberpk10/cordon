import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ClickRatePeriod } from "../../types/analysis";

// Same status-color convention as VerdictDonut.tsx (amber=warning, red=critical) — click
// and submit are two severities of the same underlying event, not unrelated categories, so
// the status palette applies rather than a generic categorical one. Single 0-100% axis for
// both series (never a dual-axis chart).
const CLICK_COLOR = "#f59e0b";
const SUBMIT_COLOR = "#ef4444";

interface ClickRateChartProps {
  periods: ClickRatePeriod[];
}

export default function ClickRateChart({ periods }: ClickRateChartProps) {
  const data = periods.map((p) => ({
    period: new Date(p.period_start).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    "Click rate": Math.round(p.click_rate * 1000) / 10,
    "Submit rate": Math.round(p.submit_rate * 1000) / 10,
  }));

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h3 className="text-base font-semibold text-slate-900">Click Rate Over Time</h3>
      <p className="text-xs text-slate-500">% of recipients per period who clicked or submitted.</p>
      {data.length === 0 ? (
        <p className="mt-4 text-sm text-slate-500">No campaigns sent in this period.</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={data} margin={{ top: 16, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" vertical={false} />
            <XAxis dataKey="period" tick={{ fontSize: 12, fill: "#64748b" }} axisLine={{ stroke: "#cbd5e1" }} tickLine={false} />
            <YAxis
              unit="%"
              allowDecimals={false}
              tick={{ fontSize: 12, fill: "#64748b" }}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip cursor={{ fill: "#f1f5f9" }} formatter={(value) => `${value}%`} />
            <Legend />
            <Bar dataKey="Click rate" fill={CLICK_COLOR} radius={[4, 4, 0, 0]} />
            <Bar dataKey="Submit rate" fill={SUBMIT_COLOR} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
