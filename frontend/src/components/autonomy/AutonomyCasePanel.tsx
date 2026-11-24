import { useCallback, useEffect, useState } from "react";
import { Bot, Undo2 } from "lucide-react";
import { decideAutonomyAction, getAutonomyActions, type AutonomyDecisionVerb } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import type { AutonomyActionLogEntry, AutonomyActionStatus } from "../../types/analysis";
import { Badge, Button, Card, ErrorState, LoadingState, type BadgeTone } from "../ui";

export const OUTCOME: Partial<Record<AutonomyActionStatus, { label: string; tone: BadgeTone }>> = {
  executed: { label: "Done", tone: "success" },
  shadow: { label: "Would have done (shadow)", tone: "violet" },
  pending_approval: { label: "Needs approval", tone: "warning" },
  above_tier: { label: "Above tier", tone: "neutral" },
  halted: { label: "Halted", tone: "danger" },
  reversed: { label: "Undone", tone: "neutral" },
  approved: { label: "Approved", tone: "accent" },
  dismissed: { label: "Dismissed", tone: "neutral" },
  execution_failed: { label: "Failed", tone: "danger" },
};

/** What Cordon's autonomy engine did, or would have done, for this case, with undo/approve
 * controls. Everything listed acts only on Cordon's own records; mailbox actions are
 * recommendations a person carries out. */
export default function AutonomyCasePanel({ caseId, onChanged }: { caseId: string; onChanged?: () => void }) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [rows, setRows] = useState<AutonomyActionLogEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(() => {
    getAutonomyActions({ caseId, pageSize: 50 })
      .then((data) => setRows(data.items.filter((r) => r.engine === "d5").reverse()))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load autonomy actions."));
  }, [caseId]);

  useEffect(load, [load]);

  const decide = async (row: AutonomyActionLogEntry, verb: AutonomyDecisionVerb) => {
    setBusy(row.id + verb);
    setError(null);
    try {
      await decideAutonomyAction(row.id, verb);
      load();
      onChanged?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : `Failed to ${verb}.`);
    } finally {
      setBusy(null);
    }
  };

  if (rows === null) {
    return <Card>{error ? <ErrorState message={error} /> : <LoadingState label="Loading autonomy…" lines={2} />}</Card>;
  }
  if (rows.length === 0) return null;

  const shadow = rows.every((r) => r.mode === "shadow");

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
          <Bot aria-hidden="true" className="h-4 w-4 text-accent" />
          Autonomy
        </h2>
        {shadow && <Badge tone="violet">Shadow mode: nothing was changed</Badge>}
      </div>
      <p className="mt-1 text-sm text-fg-secondary">
        {shadow
          ? "What Cordon would have done for this case. Turn off shadow mode under Autonomy to let it act."
          : "What Cordon did for this case. Every action is reversible and only touches Cordon's own records."}
      </p>
      {error && <ErrorState message={error} className="mt-3" />}
      <ul className="mt-4 flex flex-col divide-y divide-line">
        {rows.map((row) => {
          const outcome = OUTCOME[row.status] ?? { label: row.status, tone: "neutral" as BadgeTone };
          const description = (row.result?.description as string | undefined) ?? row.action_type;
          return (
            <li key={row.id} className="flex flex-wrap items-start justify-between gap-3 py-3">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm font-semibold text-fg">{description}</span>
                  <Badge size="sm" tone={outcome.tone}>
                    {outcome.label}
                  </Badge>
                  {row.tier && (
                    <Badge size="sm" tone="neutral" title="Autonomy tier this action belongs to">
                      {row.tier}
                    </Badge>
                  )}
                </div>
                <p className="mt-1 text-xs text-fg-muted">
                  <span className="font-mono">{row.rule_id}</span> · {row.result?.rule as string}
                </p>
                {row.undo && (
                  <p className="mt-0.5 text-xs text-fg-muted">
                    Undo: {row.undo.description}
                    {row.reversed_by && ` · undone by ${row.reversed_by}`}
                    {row.decided_by && ` · ${row.status === "dismissed" ? "dismissed" : "approved"} by ${row.decided_by}`}
                  </p>
                )}
                {row.action_type === "RECOMMEND_MAILBOX_REMEDIATION" && (
                  <p className="mt-0.5 text-xs text-fg-muted">
                    Cordon never changes your mailbox. Approving records the decision; carry it out in your mail admin.
                  </p>
                )}
              </div>
              <div className="flex gap-2">
                {row.status === "executed" && (
                  <Button
                    size="sm"
                    variant="secondary"
                    icon={Undo2}
                    loading={busy === row.id + "undo"}
                    onClick={() => decide(row, "undo")}
                  >
                    Undo
                  </Button>
                )}
                {row.status === "pending_approval" && (
                  <>
                    {isAdmin && (
                      <Button
                        size="sm"
                        variant="primary"
                        loading={busy === row.id + "approve"}
                        onClick={() => decide(row, "approve")}
                      >
                        Approve
                      </Button>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      loading={busy === row.id + "dismiss"}
                      onClick={() => decide(row, "dismiss")}
                    >
                      Dismiss
                    </Button>
                  </>
                )}
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
