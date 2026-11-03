import { ShieldCheck } from "lucide-react";
import type { Indicator, Severity } from "../types/analysis";
import { Badge, EmptyState, type BadgeTone } from "./ui";

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  low: "neutral",
  medium: "warning",
  high: "danger",
};

interface IndicatorListProps {
  indicators: Indicator[];
  emptyMessage?: string;
}

export default function IndicatorList({
  indicators,
  emptyMessage = "No phishing indicators were detected in this email.",
}: IndicatorListProps) {
  if (indicators.length === 0) {
    return (
      <div className="rounded-card border border-line bg-surface-card">
        <EmptyState variant="inline" icon={ShieldCheck} title={emptyMessage} />
      </div>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {indicators.map((indicator) => (
        <li key={indicator.id} className="rounded-card border border-line bg-surface-card p-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-semibold text-fg">{indicator.title}</h3>
            <Badge tone={SEVERITY_TONE[indicator.severity]} caps>
              {indicator.severity} · +{indicator.score}
            </Badge>
          </div>
          <p className="mt-1 text-sm text-fg-secondary">{indicator.description}</p>
          {indicator.evidence.length > 0 && (
            <ul className="mt-2 list-inside list-disc space-y-0.5 text-xs text-fg-secondary">
              {indicator.evidence.map((line, idx) => (
                <li key={idx}>{line}</li>
              ))}
            </ul>
          )}
        </li>
      ))}
    </ul>
  );
}
