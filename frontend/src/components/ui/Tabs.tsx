import { useRef, type KeyboardEvent, type ReactNode } from "react";
import clsx from "clsx";
import { focusRing } from "./styles";

export interface TabItem<T extends string> {
  value: T;
  label: ReactNode;
}

/** Arrow/Home/End keyboard movement shared by Tabs and SegmentedControl (WAI-ARIA
 * "automatic activation": moving focus also selects). */
function useRovingKeys<T extends string>(items: TabItem<T>[], value: T, onChange: (v: T) => void) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>) => {
    const index = items.findIndex((item) => item.value === value);
    let next = -1;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") next = (index + 1) % items.length;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = (index - 1 + items.length) % items.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = items.length - 1;
    if (next < 0) return;
    event.preventDefault();
    onChange(items[next].value);
    refs.current[next]?.focus();
  };
  return { refs, onKeyDown };
}

export interface TabsProps<T extends string> {
  items: TabItem<T>[];
  value: T;
  onChange: (value: T) => void;
  "aria-label": string;
  /** Prefix for tab/panel ids, so a TabPanel can reference its tab. */
  idPrefix: string;
  /** Stretch tabs to fill the row (e.g. inside a card header). */
  fitted?: boolean;
  className?: string;
}

/** Underline tabs. Pair with <TabPanel> for the content area. */
export function Tabs<T extends string>({
  items,
  value,
  onChange,
  idPrefix,
  fitted,
  className,
  ...aria
}: TabsProps<T>) {
  const { refs, onKeyDown } = useRovingKeys(items, value, onChange);
  return (
    <div role="tablist" aria-label={aria["aria-label"]} className={clsx("flex gap-1 border-b border-line", className)}>
      {items.map((item, i) => {
        const selected = item.value === value;
        return (
          <button
            key={item.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            id={`${idPrefix}-tab-${item.value}`}
            aria-selected={selected}
            aria-controls={`${idPrefix}-panel`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(item.value)}
            onKeyDown={onKeyDown}
            className={clsx(
              "-mb-px whitespace-nowrap rounded-t-control border-b-2 px-3 py-2.5 text-sm transition-colors duration-150",
              focusRing,
              fitted && "flex-1",
              selected
                ? "border-accent font-semibold text-fg"
                : "border-transparent text-fg-secondary hover:border-line-strong hover:text-fg"
            )}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}

export function TabPanel({
  idPrefix,
  value,
  className,
  children,
}: {
  idPrefix: string;
  value: string;
  className?: string;
  children: ReactNode;
}) {
  return (
    <div
      role="tabpanel"
      id={`${idPrefix}-panel`}
      aria-labelledby={`${idPrefix}-tab-${value}`}
      tabIndex={0}
      className={clsx("focus-visible:outline-none", className)}
    >
      {children}
    </div>
  );
}

export interface SegmentedControlProps<T extends string> {
  items: TabItem<T>[];
  value: T;
  onChange: (value: T) => void;
  "aria-label": string;
  size?: "sm" | "md";
  className?: string;
}

/** A compact either/or switch (e.g. Email / Activity Log). Radio-group semantics. */
export function SegmentedControl<T extends string>({
  items,
  value,
  onChange,
  size = "md",
  className,
  ...aria
}: SegmentedControlProps<T>) {
  const { refs, onKeyDown } = useRovingKeys(items, value, onChange);
  return (
    <div
      role="radiogroup"
      aria-label={aria["aria-label"]}
      className={clsx("inline-flex rounded-control border border-line bg-surface-panel p-1", className)}
    >
      {items.map((item, i) => {
        const selected = item.value === value;
        return (
          <button
            key={item.value}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="radio"
            aria-checked={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(item.value)}
            onKeyDown={onKeyDown}
            className={clsx(
              "inline-flex items-center gap-2 rounded-md font-semibold transition-colors duration-150",
              focusRing,
              size === "sm" ? "px-3 py-1 text-xs" : "px-4 py-1.5 text-sm",
              selected
                ? "bg-surface-raised text-fg shadow-sm ring-1 ring-inset ring-line-strong"
                : "text-fg-secondary hover:text-fg"
            )}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
}
