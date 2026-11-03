import type { ReactNode } from "react";
import clsx from "clsx";
import {
  AlertTriangle,
  CheckCircle2,
  Info,
  Inbox,
  XCircle,
  type LucideIcon,
} from "lucide-react";

export interface EmptyStateProps {
  icon?: LucideIcon;
  title: ReactNode;
  description?: ReactNode;
  action?: ReactNode;
  /** "inline" is a compact one-liner for inside cards/tables; "block" is a centered panel. */
  variant?: "block" | "inline";
  className?: string;
}

export function EmptyState({ icon: Icon = Inbox, title, description, action, variant = "block", className }: EmptyStateProps) {
  if (variant === "inline") {
    return (
      <div className={clsx("flex items-center justify-center gap-2 py-6 text-sm text-fg-secondary", className)}>
        <Icon aria-hidden="true" className="h-4 w-4 text-fg-muted" />
        <span>{title}</span>
      </div>
    );
  }
  return (
    <div className={clsx("flex flex-col items-center justify-center px-6 py-10 text-center", className)}>
      <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-full border border-line bg-surface-raised">
        <Icon aria-hidden="true" className="h-5 w-5 text-fg-muted" />
      </div>
      <p className="text-sm font-semibold text-fg">{title}</p>
      {description && <p className="mt-1 max-w-sm text-sm text-fg-secondary">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

/** A single shimmering placeholder bar. */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden="true" className={clsx("animate-pulse rounded-md bg-surface-raised", className)} />;
}

export interface LoadingStateProps {
  /** Announced to screen readers; also shown visually unless `variant="skeleton"`. */
  label?: string;
  /** "skeleton" shows placeholder lines; "inline" shows a small spinner + label. */
  variant?: "skeleton" | "inline";
  lines?: number;
  className?: string;
}

export function LoadingState({ label = "Loading…", variant = "skeleton", lines = 3, className }: LoadingStateProps) {
  if (variant === "inline") {
    return (
      <div role="status" className={clsx("flex items-center gap-2 py-2 text-sm text-fg-secondary", className)}>
        <span aria-hidden="true" className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-line-strong border-t-accent" />
        {label}
      </div>
    );
  }
  return (
    <div role="status" className={clsx("flex flex-col gap-2.5 py-2", className)}>
      <span className="sr-only">{label}</span>
      {Array.from({ length: lines }, (_, i) => (
        <Skeleton key={i} className={clsx("h-4", i === lines - 1 ? "w-2/3" : "w-full")} />
      ))}
    </div>
  );
}

export type AlertTone = "danger" | "warning" | "success" | "info";

const ALERT: Record<AlertTone, { icon: LucideIcon; classes: string }> = {
  danger: { icon: XCircle, classes: "border-danger/35 bg-danger/10 text-danger" },
  warning: { icon: AlertTriangle, classes: "border-warning/35 bg-warning/10 text-warning" },
  success: { icon: CheckCircle2, classes: "border-success/35 bg-success/10 text-success" },
  info: { icon: Info, classes: "border-accent/30 bg-accent/10 text-accent" },
};

export interface AlertProps {
  tone?: AlertTone;
  title?: ReactNode;
  /** Optional action (e.g. a Retry button) aligned to the right. */
  action?: ReactNode;
  className?: string;
  children?: ReactNode;
}

/** Inline status message. Errors use role="alert" so they're announced when they appear. */
export function Alert({ tone = "danger", title, action, className, children }: AlertProps) {
  const { icon: Icon, classes } = ALERT[tone];
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={clsx("flex items-start gap-3 rounded-control border px-4 py-3 text-sm", classes, className)}
    >
      <Icon aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
      <div className="min-w-0 flex-1">
        {title && <p className="font-semibold">{title}</p>}
        {children && <div className={clsx(title && "mt-0.5 text-fg-secondary")}>{children}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

/** Convenience for the common "request failed" case. */
export function ErrorState({ message, onRetry, className }: { message: ReactNode; onRetry?: () => void; className?: string }) {
  return (
    <Alert
      tone="danger"
      className={className}
      action={
        onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="text-sm font-semibold text-danger underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-danger"
          >
            Retry
          </button>
        )
      }
    >
      {message}
    </Alert>
  );
}
