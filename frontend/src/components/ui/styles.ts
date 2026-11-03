/** Class fragments shared by several primitives, kept here so focus and control styling
 * can't drift between them. */

export const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-surface-page";

export const controlBase =
  "block w-full rounded-control border border-line-strong bg-surface-raised px-3 text-sm text-fg " +
  "placeholder:text-fg-muted transition-colors duration-150 " +
  "hover:border-fg-muted/60 focus:border-accent focus:outline-none focus:ring-2 focus:ring-accent/30 " +
  "disabled:cursor-not-allowed disabled:opacity-50 " +
  "aria-[invalid=true]:border-danger aria-[invalid=true]:focus:ring-danger/30";
