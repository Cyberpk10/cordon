import type { ReactNode } from "react";
import clsx from "clsx";
import type { LucideIcon } from "lucide-react";

export type BadgeTone = "neutral" | "accent" | "success" | "warning" | "caution" | "danger" | "violet";

const TONE: Record<BadgeTone, string> = {
  neutral: "border-line-strong bg-surface-raised text-fg-secondary",
  accent: "border-accent/35 bg-accent/10 text-accent",
  success: "border-success/35 bg-success/10 text-success",
  warning: "border-warning/35 bg-warning/10 text-warning",
  caution: "border-caution/50 bg-caution/10 text-caution",
  danger: "border-danger/35 bg-danger/10 text-danger",
  violet: "border-violet/35 bg-violet/10 text-violet",
};

export interface BadgeProps {
  tone?: BadgeTone;
  size?: "sm" | "md" | "lg";
  icon?: LucideIcon;
  /** Uppercase + tracking, for short status codes like "HIGH · +25". */
  caps?: boolean;
  /** A leading status dot instead of (or alongside) an icon. */
  dot?: boolean;
  title?: string;
  className?: string;
  children: ReactNode;
}

const SIZE = {
  sm: "gap-1 px-2 py-0.5 text-[11px]",
  md: "gap-1.5 px-2.5 py-0.5 text-xs",
  lg: "gap-2 px-3.5 py-1 text-sm",
};

/** Status chip. Color always comes with text, so meaning never relies on hue alone. */
export default function Badge({ tone = "neutral", size = "md", icon: Icon, caps, dot, title, className, children }: BadgeProps) {
  return (
    <span
      title={title}
      className={clsx(
        "inline-flex items-center whitespace-nowrap rounded-full border font-semibold",
        TONE[tone],
        SIZE[size],
        caps && "uppercase tracking-wide",
        className
      )}
    >
      {dot && <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-current" />}
      {Icon && <Icon aria-hidden="true" className={size === "lg" ? "h-4 w-4" : "h-3 w-3"} />}
      {children}
    </span>
  );
}
