import type { LucideIcon } from "lucide-react";

/** Static (non-interactive) row of icon + label pills, shared by the homepage's feature
 * sections. Rendered as a list so screen readers announce the count. */
export default function FeaturePills({
  items,
  centered = false,
}: {
  items: { icon: LucideIcon; label: string }[];
  centered?: boolean;
}) {
  return (
    <ul className={`mt-10 flex flex-wrap gap-3 ${centered ? "justify-center" : ""}`}>
      {items.map((item) => (
        <li
          key={item.label}
          className="inline-flex items-center gap-2 rounded-full border border-line bg-surface-raised/70 px-5 py-2.5 text-sm text-fg"
        >
          <item.icon aria-hidden className="h-4 w-4 shrink-0 text-accent-text" />
          {item.label}
        </li>
      ))}
    </ul>
  );
}
