import type { Verdict } from "../types/analysis";
import { Badge } from "./ui";
import { VERDICT_META } from "./verdict";

interface VerdictBadgeProps {
  verdict: Verdict;
  score: number;
}

/** Compact verdict chip + colour-coded score, for tables and lists. (Full result views use
 * AnalysisResultCard's verdict header instead.) */
export default function VerdictBadge({ verdict, score }: VerdictBadgeProps) {
  const meta = VERDICT_META[verdict];
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
