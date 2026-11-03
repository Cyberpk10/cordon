/** Runtime access to the design tokens for code that can't use Tailwind classes —
 * currently just the Recharts charts, which take colors as SVG attribute strings.
 *
 * Values are read from the CSS variables in index.css (the single source of truth), so
 * changing a token there updates the charts too; nothing here duplicates a hex value. */

export type ColorToken =
  | "surface-page"
  | "surface-panel"
  | "surface-card"
  | "surface-raised"
  | "line"
  | "line-strong"
  | "fg"
  | "fg-secondary"
  | "fg-muted"
  | "fg-on-fill"
  | "accent"
  | "accent-hover"
  | "accent-text"
  | "accent-text-hover"
  | "accent-fill"
  | "accent-fill-hover"
  | "danger"
  | "danger-fill"
  | "danger-fill-hover"
  | "success"
  | "warning"
  | "caution"
  | "violet";

/** Resolves a token to a concrete `rgb(...)` string, optionally with alpha. */
export function color(name: ColorToken, alpha = 1): string {
  const channels = getComputedStyle(document.documentElement)
    .getPropertyValue(`--color-${name}`)
    .trim();
  return alpha === 1 ? `rgb(${channels})` : `rgb(${channels} / ${alpha})`;
}

/** Shared chart chrome so every chart's axes, grid, and tooltip look the same. */
export function chartTheme() {
  return {
    grid: color("line"),
    axisLine: color("line-strong"),
    tick: { fontSize: 12, fill: color("fg-muted") },
    cursor: { fill: color("surface-raised") },
    tooltip: {
      contentStyle: {
        backgroundColor: color("surface-panel"),
        border: `1px solid ${color("line")}`,
        borderRadius: 8,
        color: color("fg"),
      },
      labelStyle: { color: color("fg-secondary") },
      itemStyle: { color: color("fg") },
    },
  };
}
