import { CalendarRange } from "lucide-react";
import { Input } from "./Input";

interface DateRangeFilterProps {
  from: string;
  to: string;
  onFromChange: (value: string) => void;
  onToChange: (value: string) => void;
  /** What the range filters, for the group's accessible name (e.g. "Dashboard period"). */
  label?: string;
}

/** Compact From–To date pair sized for the top bar. Empty means "server default period". */
export default function DateRangeFilter({
  from,
  to,
  onFromChange,
  onToChange,
  label = "Date range",
}: DateRangeFilterProps) {
  return (
    // Full row on phones so both dates stay readable next to other top-bar controls.
    <div role="group" aria-label={label} className="flex min-w-0 basis-full items-center gap-2 sm:basis-auto">
      <CalendarRange aria-hidden="true" className="hidden h-4 w-4 shrink-0 text-fg-muted sm:block" />
      <Input
        type="date"
        controlSize="sm"
        aria-label="From date"
        value={from}
        max={to || undefined}
        onChange={(event) => onFromChange(event.target.value)}
        className="min-w-0 flex-1 sm:w-36 sm:flex-none"
      />
      <span aria-hidden="true" className="text-fg-muted">
        –
      </span>
      <Input
        type="date"
        controlSize="sm"
        aria-label="To date"
        value={to}
        min={from || undefined}
        onChange={(event) => onToChange(event.target.value)}
        className="min-w-0 flex-1 sm:w-36 sm:flex-none"
      />
    </div>
  );
}
