import type { SimulationCampaignStatus, SimulationRecipientStatus } from "../../types/analysis";

// Same status-color convention as VerdictBadge.tsx / VerdictDonut.tsx (emerald=good,
// amber=warning, red=critical), reused here rather than inventing a new palette.
const RECIPIENT_STYLES: Record<SimulationRecipientStatus, { label: string; classes: string }> = {
  pending: { label: "Pending", classes: "bg-slate-100 text-slate-600 border-slate-300" },
  sent: { label: "Sent", classes: "bg-sky-100 text-sky-800 border-sky-300" },
  send_failed: { label: "Send failed", classes: "bg-red-100 text-red-800 border-red-300" },
  clicked: { label: "Clicked", classes: "bg-amber-100 text-amber-800 border-amber-300" },
  submitted: { label: "Submitted", classes: "bg-red-100 text-red-800 border-red-300" },
};

const CAMPAIGN_STYLES: Record<SimulationCampaignStatus, { label: string; classes: string }> = {
  draft: { label: "Draft", classes: "bg-slate-100 text-slate-600 border-slate-300" },
  authorized: { label: "Authorized", classes: "bg-sky-100 text-sky-800 border-sky-300" },
  sending: { label: "Sending", classes: "bg-sky-100 text-sky-800 border-sky-300" },
  sent: { label: "Sent", classes: "bg-emerald-100 text-emerald-800 border-emerald-300" },
  send_failed: { label: "Send failed", classes: "bg-red-100 text-red-800 border-red-300" },
};

export function RecipientStatusBadge({ status }: { status: SimulationRecipientStatus }) {
  const style = RECIPIENT_STYLES[status];
  return (
    <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${style.classes}`}>
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
      ? "bg-red-100 text-red-800 border-red-300"
      : score >= 25
        ? "bg-amber-100 text-amber-800 border-amber-300"
        : "bg-emerald-100 text-emerald-800 border-emerald-300";
  const label = score >= 60 ? "High" : score >= 25 ? "Medium" : "Low";
  return (
    <span className="inline-flex items-center gap-2">
      <span className="text-sm font-bold text-slate-800">{score}</span>
      <span className={`rounded-full border px-2 py-0.5 text-xs font-medium ${classes}`}>{label}</span>
    </span>
  );
}
