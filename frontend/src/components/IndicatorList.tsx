import type { Indicator, Severity } from "../types/analysis";

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "bg-surface-raised text-fg border-line-strong",
  medium: "bg-warning/10 text-warning border-warning/35",
  high: "bg-danger/10 text-danger border-danger/35",
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
      <p className="rounded-lg border border-line bg-surface-panel p-4 text-sm text-fg-secondary">
        {emptyMessage}
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {indicators.map((indicator) => (
        <li key={indicator.id} className="rounded-lg border border-line bg-surface-card p-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-semibold text-fg">{indicator.title}</h3>
            <span
              className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[indicator.severity]}`}
            >
              {indicator.severity} · +{indicator.score}
            </span>
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
