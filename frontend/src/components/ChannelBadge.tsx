import type { MessageChannel } from "../types/analysis";
import { Badge, type BadgeTone } from "./ui";

const CHANNEL_STYLES: Record<MessageChannel, { label: string; tone: BadgeTone }> = {
  email: { label: "Email", tone: "neutral" },
  slack: { label: "Slack", tone: "violet" },
  teams: { label: "Teams", tone: "accent" },
};

interface ChannelBadgeProps {
  channel: MessageChannel;
}

export default function ChannelBadge({ channel }: ChannelBadgeProps) {
  const style = CHANNEL_STYLES[channel];
  return <Badge tone={style.tone}>{style.label}</Badge>;
}
