import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { MonthlyThreatCount } from "../../types/analysis";
import { chartTheme, color } from "../../theme";

function toQuarterly(monthly: MonthlyThreatCount[]): { quarter: string; count: number }[] {
  const buckets = new Map<string, number>();
  for (const { month, count } of monthly) {
    const [year, monthNum] = month.split("-");
    const quarter = Math.ceil(Number(monthNum) / 3);
    const key = `${year} Q${quarter}`;
    buckets.set(key, (buckets.get(key) ?? 0) + count);
  }
  return Array.from(buckets.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([quarter, count]) => ({ quarter, count }));
}

interface ThreatTrendChartProps {
  monthlyTrend: MonthlyThreatCount[];
}

export default function ThreatTrendChart({ monthlyTrend }: ThreatTrendChartProps) {
  const data = toQuarterly(monthlyTrend);
  const chart = chartTheme();

  return (
    <div className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
      <h3 className="text-base font-semibold text-fg">Quarterly Threat Trend</h3>
      <p className="text-xs text-fg-secondary">Suspicious + malicious cases, bucketed by quarter.</p>
      {data.length === 0 ? (
        <p className="mt-4 text-sm text-fg-secondary">No threats in this period.</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={data} margin={{ top: 16, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={chart.grid} vertical={false} />
            <XAxis
              dataKey="quarter"
              tick={chart.tick}
              axisLine={{ stroke: chart.axisLine }}
              tickLine={false}
            />
            <YAxis allowDecimals={false} tick={chart.tick} axisLine={false} tickLine={false} />
            <Tooltip cursor={chart.cursor} {...chart.tooltip} />
            <Bar dataKey="count" fill={color("accent")} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
