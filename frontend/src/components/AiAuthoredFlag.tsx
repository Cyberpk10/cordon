import { Bot } from "lucide-react";
import type { Indicator } from "../types/analysis";
import { Badge, Card } from "./ui";

interface AiAuthoredFlagProps {
  indicators: Indicator[];
}

export default function AiAuthoredFlag({ indicators }: AiAuthoredFlagProps) {
  const indicator = indicators.find((i) => i.id === "AI_AUTHORED_SUSPECTED");
  if (!indicator) {
    return null;
  }

  const reason = indicator.evidence[0] ?? indicator.description;

  return (
    <Card tone="violet" padding="sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold uppercase tracking-wide text-violet">
          <Bot aria-hidden="true" className="h-4 w-4" />
          Likely AI-generated
        </h2>
        <Badge tone="violet">
          {indicator.evidence.length} stylistic signal{indicator.evidence.length === 1 ? "" : "s"}
        </Badge>
      </div>
      <p className="mt-1 text-sm text-fg-secondary">{reason}</p>
    </Card>
  );
}
