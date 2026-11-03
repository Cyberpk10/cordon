import { Tag } from "lucide-react";
import type { Label, Verdict } from "../types/analysis";
import { Badge, Button, Card, ErrorState, Field, Input, Select } from "./ui";
import { VERDICT_META } from "./verdict";

/** The latest human label, shown inside the verdict card. Calls out when the analyst's
 * verdict differs from the machine's, since that's the case an auditor will ask about. */
export function HumanLabelNote({ label, machineVerdict }: { label: Label; machineVerdict: Verdict }) {
  const meta = VERDICT_META[label.analyst_verdict];
  const overrides = label.analyst_verdict !== machineVerdict;
  return (
    <div className="flex flex-col gap-1 rounded-control border border-line bg-surface-panel px-3 py-2.5 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Tag aria-hidden="true" className="h-4 w-4 text-fg-muted" />
        <span className="font-semibold text-fg">Analyst label</span>
        <Badge tone={meta.tone} icon={meta.icon} size="sm">
          {meta.label}
        </Badge>
        {overrides && (
          <Badge tone="accent" size="sm">
            Overrides machine verdict
          </Badge>
        )}
        <span className="text-xs text-fg-muted">
          {label.labeled_by} · {new Date(label.created_at).toLocaleString()}
        </span>
      </div>
      {label.note && <p className="text-fg-secondary">“{label.note}”</p>}
    </div>
  );
}

interface AnalystFeedbackCardProps {
  /** "case" or "incident" — only used in the explanatory copy. */
  noun: string;
  verdict: Verdict;
  note: string;
  onVerdictChange: (verdict: Verdict) => void;
  onNoteChange: (note: string) => void;
  onSubmit: () => void;
  isSubmitting: boolean;
  error: string | null;
}

/** Agree with or correct the machine verdict. Shared by case and incident detail. */
export function AnalystFeedbackCard({
  noun,
  verdict,
  note,
  onVerdictChange,
  onNoteChange,
  onSubmit,
  isSubmitting,
  error,
}: AnalystFeedbackCardProps) {
  return (
    <Card>
      <h2 className="text-base font-semibold text-fg">Analyst Feedback</h2>
      <p className="mt-1 text-sm text-fg-secondary">
        Agree with the machine verdict as-is, or change it below before submitting to correct it.
        Submitting again relabels the {noun} — the prior label stays in history.
      </p>
      <form
        className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end"
        onSubmit={(event) => {
          event.preventDefault();
          onSubmit();
        }}
      >
        <Field label="Verdict">
          <Select
            value={verdict}
            onChange={(event) => onVerdictChange(event.target.value as Verdict)}
            className="sm:w-40"
          >
            <option value="safe">Safe</option>
            <option value="suspicious">Suspicious</option>
            <option value="malicious">Malicious</option>
          </Select>
        </Field>
        <Field label="Note (optional)" className="flex-1">
          <Input
            type="text"
            value={note}
            onChange={(event) => onNoteChange(event.target.value)}
            placeholder="Why are you agreeing or correcting this verdict?"
          />
        </Field>
        <Button type="submit" variant="primary" loading={isSubmitting} loadingText="Submitting…">
          Submit Label
        </Button>
      </form>
      {error && <ErrorState message={error} className="mt-3" />}
    </Card>
  );
}
