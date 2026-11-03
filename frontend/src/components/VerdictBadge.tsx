import type { Verdict } from "../types/analysis";
import { Badge } from "./ui";
import { VERDICT_META } from "./verdict";

interface VerdictBadgeProps {
  verdict: Verdict;
  score: number;
  /** Table-friendly: smaller chip and a bare "/100" instead of "/ 100 risk score". */
  compact?: boolean;
}

export default function VerdictBadge({ verdict, score, compact = false }: VerdictBadgeProps) {
  const meta = VERDICT_META[verdict];

  if (compact) {
    return (
      <div className="flex items-center gap-2 whitespace-nowrap">
        <Badge tone={meta.tone} icon={meta.icon}>
          {meta.label}
        </Badge>
        <span className={`text-sm font-semibold tabular-nums ${meta.text}`}>
          {score}
          <span className="sr-only"> out of 100 risk score</span>
        </span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-3">
      <Badge tone={meta.tone} size="lg" icon={meta.icon}>
        {meta.label}
      </Badge>
      <div className="whitespace-nowrap text-fg">
        <span className="text-xl font-semibold tabular-nums">{score}</span>
        <span className="text-xs text-fg-secondary"> / 100 risk score</span>
      </div>
    </div>
  );
}
