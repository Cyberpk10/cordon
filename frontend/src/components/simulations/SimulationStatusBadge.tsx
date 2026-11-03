import type { SimulationCampaignStatus, SimulationRecipientStatus } from "../../types/analysis";

// Same status-color convention as VerdictBadge.tsx / VerdictDonut.tsx (emerald=good,
// amber=warning, red=critical), reused here rather than inventing a new palette.
const RECIPIENT_STYLES: Record<SimulationRecipientStatus, { label: string; classes: string }> = {
  pending: { label: "Pending", classes: "bg-surface-raised text-fg-secondary border-line-strong" },
  sent: { label: "Sent", classes: "bg-accent/10 text-accent border-accent/35" },
  send_failed: { label: "Send failed", classes: "bg-danger/10 text-danger border-danger/35" },
  clicked: { label: "Clicked", classes: "bg-warning/10 text-warning border-warning/35" },
  submitted: { label: "Submitted", classes: "bg-danger/10 text-danger border-danger/35" },
};

const CAMPAIGN_STYLES: Record<SimulationCampaignStatus, { label: string; classes: string }> = {
  draft: { label: "Draft", classes: "bg-surface-raised text-fg-secondary border-line-strong" },
  authorized: { label: "Authorized", classes: "bg-accent/10 text-accent border-accent/35" },
  sending: { label: "Sending", classes: "bg-accent/10 text-accent border-accent/35" },
  sent: { label: "Sent", classes: "bg-success/10 text-success border-success/35" },
  send_failed: { label: "Send failed", classes: "bg-danger/10 text-danger border-danger/35" },
};

export function RecipientStatusBadge({ status }: { status: SimulationRecipientStatus }) {
  const style = RECIPIENT_STYLES[status];
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${style.classes}`}>
      {style.label}
    </span>
  );
}

export function CampaignStatusBadge({ status }: { status: SimulationCampaignStatus }) {
  const style = CAMPAIGN_STYLES[status];
  return (
    <span className={`inline-flex items-center rounded-full border px-3 py-1 text-sm font-semibold ${style.classes}`}>
      {style.label}
    </span>
  );
}

export function RiskScoreBadge({ score }: { score: number }) {
  const classes =
    score >= 60
      ? "bg-danger/10 text-danger border-danger/35"
      : score >= 25
        ? "bg-warning/10 text-warning border-warning/35"
        : "bg-success/10 text-success border-success/35";
  const label = score >= 60 ? "High" : score >= 25 ? "Medium" : "Low";
  return (
    <span className="inline-flex items-center gap-2">
      <span className="text-sm font-semibold text-fg">{score}</span>
      <span className={`rounded-full border px-2 py-0.5 text-xs font-semibold ${classes}`}>{label}</span>
    </span>
  );
}
