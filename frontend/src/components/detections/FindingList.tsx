import { Radar } from "lucide-react";
import type { Finding, Severity } from "../../types/analysis";
import { Badge, EmptyState, type BadgeTone } from "../ui";

const SEVERITY_TONE: Record<Severity, BadgeTone> = {
  low: "neutral",
  medium: "warning",
  high: "danger",
};

interface FindingListProps {
  findings: Finding[];
  /** Gives each item an id (`${idPrefix}${finding.id}`) so summaries can link to it. */
  idPrefix?: string;
}

export default function FindingList({ findings, idPrefix }: FindingListProps) {
  if (findings.length === 0) {
    return (
      <div className="rounded-card border border-line bg-surface-card">
        <EmptyState variant="inline" icon={Radar} title="No detections fired for this incident." />
      </div>
    );
  }

  return (
    <ul className="flex flex-col gap-3">
      {findings.map((finding) => (
        <li
          key={finding.id}
          id={idPrefix ? `${idPrefix}${finding.id}` : undefined}
          className="scroll-mt-24 rounded-card border border-line bg-surface-card p-4 shadow-sm target:border-accent/60 target:ring-1 target:ring-accent/40"
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 className="font-semibold text-fg">{finding.title}</h3>
            <Badge tone={SEVERITY_TONE[finding.severity]} caps>
              {finding.severity} · +{finding.points}
            </Badge>
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
