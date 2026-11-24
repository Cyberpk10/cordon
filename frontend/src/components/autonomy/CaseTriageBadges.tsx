import { Layers } from "lucide-react";
import type { CasePriority, CaseStatus } from "../../types/analysis";
import { Badge, type BadgeTone } from "../ui";

const PRIORITY_TONE: Record<CasePriority, BadgeTone> = {
  low: "neutral",
  medium: "caution",
  high: "warning",
  critical: "danger",
};

const STATUS_LABEL: Record<CaseStatus, string> = {
  new: "New",
  triaged: "Triaged",
  escalated: "Escalated",
  resolved: "Resolved",
};

/** Triage state set by people or by Cordon's reversible autonomy actions. Renders nothing for
 * an untouched case. */
export default function CaseTriageBadges({
  status,
  priority,
  tags,
  campaignId,
  size = "sm",
}: {
  status?: CaseStatus;
  priority?: CasePriority | null;
  tags?: string[];
  campaignId?: string | null;
  size?: "sm" | "md";
}) {
  const showStatus = status && status !== "new";
  if (!showStatus && !priority && !tags?.length && !campaignId) return null;
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5">
      {showStatus && (
        <Badge size={size} tone={status === "escalated" ? "danger" : "neutral"}>
          {STATUS_LABEL[status]}
        </Badge>
      )}
      {priority && (
        <Badge size={size} tone={PRIORITY_TONE[priority]} caps>
          {priority}
        </Badge>
      )}
      {campaignId && (
        <Badge size={size} tone="violet" icon={Layers}>
          Campaign
        </Badge>
      )}
      {tags?.map((t) => (
        <Badge key={t} size={size} tone="accent">
          {t.replace(/-/g, " ")}
        </Badge>
      ))}
    </span>
  );
}
