import { Sparkles } from "lucide-react";
import { Badge, Card } from "./ui";

interface AIAnalystSummaryProps {
  narrative: string | null;
  model: string | null;
}

export default function AIAnalystSummary({ narrative, model }: AIAnalystSummaryProps) {
  if (!narrative) {
    return null;
  }

  return (
    <Card tone="accent">
      <div className="flex items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
          <Sparkles aria-hidden="true" className="h-4 w-4 text-accent" />
          AI Analyst Summary
        </h2>
        {model && <Badge tone="accent">{model}</Badge>}
      </div>
      <p className="mt-2 text-sm leading-relaxed text-fg-secondary">{narrative}</p>
    </Card>
  );
}
