import { forwardRef, type ButtonHTMLAttributes } from "react";
import clsx from "clsx";
import { Loader2, type LucideIcon } from "lucide-react";
import { focusRing } from "./styles";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "link";
export type ButtonTone = "neutral" | "danger" | "success";
export type ButtonSize = "sm" | "md" | "lg";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  /** Colors a secondary/ghost button for a destructive or affirmative action without
   * making it a solid fill (e.g. "Reject" next to a primary "Approve"). */
  tone?: ButtonTone;
  size?: ButtonSize;
  /** Shows a spinner, disables the button, and sets aria-busy. The label stays visible
   * (or is replaced by `loadingText`) so the button never changes meaning mid-action. */
  loading?: boolean;
  loadingText?: string;
  icon?: LucideIcon;
  /** Places `icon` after the label instead of before it. */
  iconPosition?: "start" | "end";
  fullWidth?: boolean;
}

const VARIANT: Record<Exclude<ButtonVariant, "secondary" | "ghost">, string> = {
  primary: "bg-accent-fill text-fg-on-fill shadow-sm hover:bg-accent-fill-hover",
  danger: "bg-danger-fill text-fg-on-fill shadow-sm hover:bg-danger-fill-hover",
  link: "text-accent hover:text-accent-hover hover:underline underline-offset-2",
};

const SECONDARY: Record<ButtonTone, string> = {
  neutral: "border border-line-strong bg-surface-card text-fg hover:bg-surface-raised",
  danger: "border border-danger/35 bg-surface-card text-danger hover:bg-danger/10",
  success: "border border-success/35 bg-surface-card text-success hover:bg-success/10",
};

const GHOST: Record<ButtonTone, string> = {
  neutral: "text-fg-secondary hover:bg-surface-raised hover:text-fg",
  danger: "text-danger hover:bg-danger/10",
  success: "text-success hover:bg-success/10",
};

const SIZE: Record<ButtonSize, string> = {
  sm: "h-8 gap-1.5 px-3 text-xs",
  md: "h-9 gap-2 px-4 text-sm",
  lg: "h-10 gap-2 px-5 text-sm",
};

const ICON_SIZE: Record<ButtonSize, string> = { sm: "h-3.5 w-3.5", md: "h-4 w-4", lg: "h-4 w-4" };

const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  {
    variant = "secondary",
    tone = "neutral",
    size = "md",
    loading = false,
    loadingText,
    icon: Icon,
    iconPosition = "start",
    fullWidth = false,
    type = "button",
    disabled,
    className,
    children,
    ...rest
  },
  ref
) {
  const isLink = variant === "link";
  const variantClass =
    variant === "secondary" ? SECONDARY[tone] : variant === "ghost" ? GHOST[tone] : VARIANT[variant];
  const iconEl = loading ? (
    <Loader2 aria-hidden="true" className={clsx(ICON_SIZE[size], "animate-spin")} />
  ) : Icon ? (
    <Icon aria-hidden="true" className={ICON_SIZE[size]} />
  ) : null;

  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={clsx(
        "inline-flex shrink-0 items-center justify-center whitespace-nowrap font-semibold transition-colors duration-150",
        "disabled:cursor-not-allowed disabled:opacity-50",
        focusRing,
        isLink ? "gap-1.5 rounded text-sm" : clsx("rounded-control", SIZE[size]),
        variantClass,
        fullWidth && "w-full",
        className
      )}
      {...rest}
    >
      {iconPosition === "start" && iconEl}
      {loading && loadingText ? loadingText : children}
      {iconPosition === "end" && iconEl}
    </button>
  );
});

export default Button;
