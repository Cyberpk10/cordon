import { PieChart as PieChartIcon } from "lucide-react";
import { Cell, Legend, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import type { VerdictCounts } from "../../types/analysis";
import { EmptyState } from "../ui";
import { chartTheme, color, type ColorToken } from "../../theme";
import { Card } from "../ui";

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
    <Card as="div">
      <h3 className="text-base font-semibold text-fg">Verdict Distribution</h3>
      {total === 0 ? (
        <EmptyState icon={PieChartIcon} title="No cases in this period." className="mt-4" />
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
    </Card>
  );
}
