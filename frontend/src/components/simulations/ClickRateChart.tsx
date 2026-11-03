import { BarChart3 } from "lucide-react";
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { ClickRatePeriod } from "../../types/analysis";
import { EmptyState } from "../ui";
import { chartTheme, color } from "../../theme";
import { Card } from "../ui";

// Same status-color convention as VerdictDonut.tsx (amber=warning, red=critical) — click
// and submit are two severities of the same underlying event, not unrelated categories, so
// the status palette applies rather than a generic categorical one. Single 0-100% axis for
// both series (never a dual-axis chart).

interface ClickRateChartProps {
  periods: ClickRatePeriod[];
}

export default function ClickRateChart({ periods }: ClickRateChartProps) {
  const chart = chartTheme();
  const data = periods.map((p) => ({
    period: new Date(p.period_start).toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    "Click rate": Math.round(p.click_rate * 1000) / 10,
    "Submit rate": Math.round(p.submit_rate * 1000) / 10,
  }));

  return (
    <Card as="div">
      <h3 className="text-base font-semibold text-fg">Click Rate Over Time</h3>
      <p className="text-xs text-fg-secondary">% of recipients per period who clicked or submitted.</p>
      {data.length === 0 ? (
        <EmptyState icon={BarChart3} title="No campaigns sent in this period." className="mt-4" />
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <BarChart data={data} margin={{ top: 16, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke={chart.grid} vertical={false} />
            <XAxis dataKey="period" tick={chart.tick} axisLine={{ stroke: chart.axisLine }} tickLine={false} />
            <YAxis
              unit="%"
              allowDecimals={false}
              tick={chart.tick}
              axisLine={false}
              tickLine={false}
            />
            <Tooltip cursor={chart.cursor} {...chart.tooltip} formatter={(value) => `${value}%`} />
            <Legend />
            <Bar dataKey="Click rate" fill={color("warning")} radius={[4, 4, 0, 0]} />
            <Bar dataKey="Submit rate" fill={color("danger")} radius={[4, 4, 0, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </Card>
  );
}
