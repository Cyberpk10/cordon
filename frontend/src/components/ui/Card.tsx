import type { HTMLAttributes, ReactNode } from "react";
import clsx from "clsx";

type Padding = "none" | "sm" | "md" | "lg";
const PADDING: Record<Padding, string> = { none: "", sm: "p-4", md: "p-5", lg: "p-6" };

export interface CardProps extends HTMLAttributes<HTMLElement> {
  padding?: Padding;
  /** Renders as a <section> (default) or a plain <div>. */
  as?: "section" | "div" | "article";
  /** A tinted status card (e.g. the AI-authored flag); defaults to the neutral surface. */
  tone?: "default" | "accent" | "violet" | "warning" | "danger" | "success" | "caution";
}

const TONE: Record<NonNullable<CardProps["tone"]>, string> = {
  default: "border-line bg-surface-card",
  accent: "border-accent/25 bg-accent/10",
  violet: "border-violet/35 bg-violet/10",
  warning: "border-warning/35 bg-warning/10",
  danger: "border-danger/35 bg-danger/10",
  success: "border-success/35 bg-success/10",
  caution: "border-caution/50 bg-caution/10",
};

export function Card({ padding = "lg", as: Tag = "section", tone = "default", className, ...rest }: CardProps) {
  return (
    <Tag
      className={clsx("overflow-hidden rounded-card border shadow-sm", TONE[tone], PADDING[padding], className)}
      {...rest}
    />
  );
}

export interface CardHeaderProps {
  title: ReactNode;
  description?: ReactNode;
  /** Right-aligned controls (buttons, links, filters). */
  actions?: ReactNode;
  /** Heading level for document outline; visual size is the same. */
  level?: 2 | 3;
  className?: string;
}

/** The header strip used on table/list cards: title + optional description and actions,
 * separated from the body by a divider. Use inside a `<Card padding="none">`. */
export function CardHeader({ title, description, actions, level = 3, className }: CardHeaderProps) {
  const Heading = level === 2 ? "h2" : "h3";
  return (
    <div
      className={clsx(
        "flex flex-wrap items-start justify-between gap-3 border-b border-line bg-surface-panel px-6 py-4",
        className
      )}
    >
      <div className="min-w-0">
        <Heading className="text-base font-semibold text-fg">{title}</Heading>
        {description && <p className="mt-0.5 text-xs text-fg-secondary">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CardBody({ className, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return <div className={clsx("px-6 py-5", className)} {...rest} />;
}

/** A section title above a group of cards (e.g. "Indicators", "Framework Mapping"). */
export function SectionHeading({ children, actions, className }: { children: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <div className={clsx("mb-3 flex items-center justify-between gap-3", className)}>
      <h2 className="text-base font-semibold text-fg">{children}</h2>
      {actions}
    </div>
  );
}
