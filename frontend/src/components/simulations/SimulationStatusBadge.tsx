import type { SimulationCampaignStatus, SimulationRecipientStatus } from "../../types/analysis";
import { Badge, type BadgeTone } from "../ui";

// Same status-color convention as VerdictBadge.tsx / VerdictDonut.tsx (success=good,
// warning=warning, danger=critical), reused here rather than inventing a new palette.
const RECIPIENT_STYLES: Record<SimulationRecipientStatus, { label: string; tone: BadgeTone }> = {
  pending: { label: "Pending", tone: "neutral" },
  sent: { label: "Sent", tone: "accent" },
  send_failed: { label: "Send failed", tone: "danger" },
  clicked: { label: "Clicked", tone: "warning" },
  submitted: { label: "Submitted", tone: "danger" },
};

const CAMPAIGN_STYLES: Record<SimulationCampaignStatus, { label: string; tone: BadgeTone }> = {
  draft: { label: "Draft", tone: "neutral" },
  authorized: { label: "Authorized", tone: "accent" },
  sending: { label: "Sending", tone: "accent" },
  sent: { label: "Sent", tone: "success" },
  send_failed: { label: "Send failed", tone: "danger" },
};

export function RecipientStatusBadge({ status }: { status: SimulationRecipientStatus }) {
  const style = RECIPIENT_STYLES[status];
  return <Badge tone={style.tone}>{style.label}</Badge>;
}

export function CampaignStatusBadge({ status }: { status: SimulationCampaignStatus }) {
  const style = CAMPAIGN_STYLES[status];
  return (
    <Badge tone={style.tone} size="lg">
      {style.label}
    </Badge>
  );
}

export function RiskScoreBadge({ score }: { score: number }) {
  const tone: BadgeTone = score >= 60 ? "danger" : score >= 25 ? "warning" : "success";
  const label = score >= 60 ? "High" : score >= 25 ? "Medium" : "Low";
  return (
    <span className="inline-flex items-center gap-2">
      <span className="text-sm font-semibold tabular-nums text-fg">{score}</span>
      <Badge tone={tone} size="sm">
        {label}
      </Badge>
    </span>
  );
}
