import type { DashboardSummary } from "../../types/analysis";
import { Card } from "../ui";

type Tone = "positive-up" | "negative-up" | "neutral";

interface DeltaBadgeProps {
  delta: number;
  deltaPct: number | null;
  tone: Tone;
}

function DeltaBadge({ delta, deltaPct, tone }: DeltaBadgeProps) {
  if (delta === 0) {
    return <span className="text-xs font-semibold text-fg-muted">No change</span>;
  }

  const isUp = delta > 0;
  const colorClass =
    tone === "neutral" ? "text-fg-secondary" : (tone === "positive-up") === isUp ? "text-success" : "text-danger";

  return (
    <span className={`text-xs font-semibold ${colorClass}`}>
      {isUp ? "▲" : "▼"} {Math.abs(delta)}
      {deltaPct !== null && ` (${deltaPct > 0 ? "+" : ""}${deltaPct}%)`}
    </span>
  );
}

const VERDICT_CARDS: { key: keyof DashboardSummary["verdict_counts"]; label: string; tone: Tone }[] = [
  { key: "malicious", label: "Malicious", tone: "negative-up" },
  { key: "suspicious", label: "Suspicious", tone: "negative-up" },
  { key: "safe", label: "Safe", tone: "positive-up" },
];

interface KpiCardsProps {
  summary: DashboardSummary;
}

export default function KpiCards({ summary }: KpiCardsProps) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <Card padding="md" as="div">
        <p className="text-sm font-semibold text-fg-secondary">Total Analyzed</p>
        <p className="mt-1 text-3xl font-semibold text-fg">{summary.total_analyzed.current}</p>
        <div className="mt-1">
          <DeltaBadge
            delta={summary.total_analyzed.delta}
            deltaPct={summary.total_analyzed.delta_pct}
            tone="neutral"
          />
        </div>
      </Card>
      {VERDICT_CARDS.map(({ key, label, tone }) => {
        const periodCount = summary.verdict_counts[key];
        return (
          <Card padding="md" as="div" key={key}>
            <p className="text-sm font-semibold text-fg-secondary">{label}</p>
            <p className="mt-1 text-3xl font-semibold text-fg">{periodCount.current}</p>
            <div className="mt-1">
              <DeltaBadge delta={periodCount.delta} deltaPct={periodCount.delta_pct} tone={tone} />
            </div>
          </Card>
        );
      })}
    </div>
  );
}
