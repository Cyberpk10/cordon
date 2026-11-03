import type { Verdict } from "../types/analysis";

const VERDICT_STYLES: Record<Verdict, { label: string; classes: string }> = {
  safe: { label: "Safe", classes: "bg-success/10 text-success border-success/35" },
  suspicious: { label: "Suspicious", classes: "bg-warning/10 text-warning border-warning/35" },
  malicious: { label: "Malicious", classes: "bg-danger/10 text-danger border-danger/35" },
};

interface VerdictBadgeProps {
  verdict: Verdict;
  score: number;
}

export default function VerdictBadge({ verdict, score }: VerdictBadgeProps) {
  const style = VERDICT_STYLES[verdict];

  return (
    <div className="flex items-center gap-4">
      <span
        className={`inline-flex items-center rounded-full border px-4 py-1.5 text-lg font-semibold ${style.classes}`}
      >
        {style.label}
      </span>
      <div className="text-fg">
        <span className="text-2xl font-semibold">{score}</span>
        <span className="text-sm text-fg-secondary"> / 100 risk score</span>
      </div>
    </div>
  );
}
