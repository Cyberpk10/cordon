import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { VerdictCounts } from "../../types/analysis";
import { chartTheme, color, type ColorToken } from "../../theme";

// Same verdict -> status-token convention as VerdictBadge.tsx (success/warning/danger).
// Legend + direct segment labels mean the chart never relies on fill color alone.
const VERDICT_TOKENS: Record<string, ColorToken> = {
  Safe: "success",
  Suspicious: "warning",
  Malicious: "danger",
};

interface VerdictDonutProps {
  verdictCounts: VerdictCounts;
}

export default function VerdictDonut({ verdictCounts }: VerdictDonutProps) {
  const data = [
    { name: "Safe", value: verdictCounts.safe.current },
    { name: "Suspicious", value: verdictCounts.suspicious.current },
    { name: "Malicious", value: verdictCounts.malicious.current },
  ];
  const total = data.reduce((sum, d) => sum + d.value, 0);
  const chart = chartTheme();

  return (
    <div className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
      <h3 className="text-base font-semibold text-fg">Verdict Distribution</h3>
      {total === 0 ? (
        <p className="mt-4 text-sm text-fg-secondary">No cases in this period.</p>
      ) : (
        <ResponsiveContainer width="100%" height={260}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={60}
              outerRadius={90}
              paddingAngle={2}
              stroke={color("surface-card")}
              label={(entry: { name?: string; value?: number }) => `${entry.name}: ${entry.value}`}
            >
              {data.map((entry) => (
                <Cell key={entry.name} fill={color(VERDICT_TOKENS[entry.name])} />
              ))}
            </Pie>
            <Tooltip {...chart.tooltip} />
            <Legend />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
