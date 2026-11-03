import type {
  HTMLAttributes,
  KeyboardEvent,
  ReactNode,
  TdHTMLAttributes,
  ThHTMLAttributes,
} from "react";
import clsx from "clsx";

/** Scroll container: tables scroll horizontally inside their card on narrow screens
 * instead of clipping or pushing the page sideways. */
export function TableContainer({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={clsx("w-full overflow-x-auto", className)}>{children}</div>;
}

export function Table({ className, ...rest }: HTMLAttributes<HTMLTableElement>) {
  return <table className={clsx("w-full text-left text-sm", className)} {...rest} />;
}

export function THead({ className, ...rest }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead
      className={clsx(
        "border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary",
        className
      )}
      {...rest}
    />
  );
}

export function TBody({ className, ...rest }: HTMLAttributes<HTMLTableSectionElement>) {
  return <tbody className={clsx("divide-y divide-line", className)} {...rest} />;
}

/** "none" leaves padding to the caller, for cells with bespoke spacing. */
type Density = "compact" | "comfortable" | "none";
const CELL_PAD: Record<Density, string> = { compact: "px-4 py-3", comfortable: "px-6 py-3", none: "" };

export function TH({
  density = "compact",
  className,
  ...rest
}: ThHTMLAttributes<HTMLTableCellElement> & { density?: Density }) {
  return <th scope="col" className={clsx(CELL_PAD[density], "whitespace-nowrap font-semibold", className)} {...rest} />;
}

export function TD({
  density = "compact",
  className,
  ...rest
}: TdHTMLAttributes<HTMLTableCellElement> & { density?: Density }) {
  return <td className={clsx(CELL_PAD[density], className)} {...rest} />;
}

export interface TRProps extends HTMLAttributes<HTMLTableRowElement> {
  /** Makes the whole row an action: hover state, pointer, and keyboard activation
   * (Tab to focus, Enter/Space to open) so it isn't mouse-only. */
  onActivate?: () => void;
  selected?: boolean;
}

export function TR({ onActivate, selected, className, ...rest }: TRProps) {
  const interactive = Boolean(onActivate);
  const onKeyDown = (event: KeyboardEvent<HTMLTableRowElement>) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onActivate?.();
    }
  };
  return (
    <tr
      onClick={onActivate}
      onKeyDown={interactive ? onKeyDown : undefined}
      tabIndex={interactive ? 0 : undefined}
      aria-selected={selected || undefined}
      className={clsx(
        "transition-colors duration-150",
        interactive &&
          "cursor-pointer hover:bg-surface-raised focus-visible:bg-surface-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent",
        selected && "bg-surface-raised",
        className
      )}
      {...rest}
    />
  );
}

/** A full-width row for empty/loading/error states inside a table body. */
export function TableMessageRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-2">
        {children}
      </td>
    </tr>
  );
}
