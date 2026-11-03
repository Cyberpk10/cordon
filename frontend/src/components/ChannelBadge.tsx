import type { MessageChannel } from "../types/analysis";

const CHANNEL_STYLES: Record<MessageChannel, { label: string; classes: string }> = {
  email: { label: "Email", classes: "bg-surface-raised text-fg border-line-strong" },
  slack: { label: "Slack", classes: "bg-violet/10 text-violet border-violet/35" },
  teams: { label: "Teams", classes: "bg-accent/10 text-accent border-accent/35" },
};

interface ChannelBadgeProps {
  channel: MessageChannel;
}

export default function ChannelBadge({ channel }: ChannelBadgeProps) {
  const style = CHANNEL_STYLES[channel];

  return (
    <span
      className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${style.classes}`}
    >
      {style.label}
    </span>
  );
}
