import type { ReactNode } from "react";

/** The title bar on every framed product surface (hero case panel, inbox preview,
 * screenshot frames): three decorative dots, an optional label, an optional right slot.
 * Matches the app's card header (panel surface, hairline divider). */
export default function WindowChrome({ title, right }: { title?: string; right?: ReactNode }) {
  return (
    <div className="flex items-center gap-1.5 border-b border-line bg-surface-panel px-4 py-3">
      <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-line-strong" />
      <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-line-strong" />
      <span aria-hidden className="h-2.5 w-2.5 rounded-full bg-line-strong" />
      {title && <span className="ml-2 text-xs text-fg-muted">{title}</span>}
      {right && <span className="ml-auto">{right}</span>}
    </div>
  );
}
