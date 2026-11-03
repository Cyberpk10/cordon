import { ShieldAlert, ShieldCheck, ShieldX, type LucideIcon } from "lucide-react";
import type { Verdict } from "../types/analysis";
import { Badge, type BadgeTone } from "./ui";

const VERDICT_STYLES: Record<Verdict, { label: string; tone: BadgeTone; icon: LucideIcon }> = {
  safe: { label: "Safe", tone: "success", icon: ShieldCheck },
  suspicious: { label: "Suspicious", tone: "warning", icon: ShieldAlert },
  malicious: { label: "Malicious", tone: "danger", icon: ShieldX },
};

interface VerdictBadgeProps {
  verdict: Verdict;
  score: number;
}

export default function VerdictBadge({ verdict, score }: VerdictBadgeProps) {
  const style = VERDICT_STYLES[verdict];

  return (
    <div className="flex items-center gap-3">
      <Badge tone={style.tone} size="lg" icon={style.icon}>
        {style.label}
      </Badge>
      <div className="whitespace-nowrap text-fg">
        <span className="text-xl font-semibold tabular-nums">{score}</span>
        <span className="text-xs text-fg-secondary"> / 100 risk score</span>
      </div>
    </div>
  );
}
