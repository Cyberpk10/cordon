import type { Finding, Severity } from "../../types/analysis";

const SEVERITY_STYLES: Record<Severity, string> = {
  low: "bg-surface-raised text-fg border-line-strong",
  medium: "bg-warning/10 text-warning border-warning/35",
  high: "bg-danger/10 text-danger border-danger/35",
};

interface FindingListProps {
  findings: Finding[];
}

export default function FindingList({ findings }: FindingListProps) {
  if (findings.length === 0) {
    return (
      <p className="rounded-lg border border-line bg-surface-panel p-4 text-sm text-fg-secondary">
        No detections fired for this incident.
      </p>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {findings.map((finding) => (
        <li key={finding.id} className="rounded-lg border border-line bg-surface-card p-4 shadow-sm">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-semibold text-fg">{finding.title}</h3>
            <span
              className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[finding.severity]}`}
            >
              {finding.severity} · +{finding.points}
            </span>
          </div>
          <p className="mt-1 text-sm text-fg-secondary">{finding.description}</p>
          <p className="mt-2 text-xs text-fg-secondary">
            {finding.evidence_event_ids.length} triggering event
            {finding.evidence_event_ids.length === 1 ? "" : "s"} — see Evidence below.
          </p>
        </li>
      ))}
    </ul>
  );
}
