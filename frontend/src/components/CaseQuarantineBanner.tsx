import { useCallback, useEffect, useState } from "react";
import { getCaseMailboxActions, undoMailboxAction, type MailboxAction } from "../api/client";
import { Alert, Button, useToast } from "./ui";

/** D7: shown on a case Cordon moved out of the owner's inbox. Undo queues a restore that the
 * Gmail add-on carries out on its next run. */
export default function CaseQuarantineBanner({ caseId }: { caseId: string }) {
  const [actions, setActions] = useState<MailboxAction[]>([]);
  const [busy, setBusy] = useState(false);
  const toast = useToast();

  const load = useCallback(async () => {
    try {
      setActions((await getCaseMailboxActions(caseId)).actions);
    } catch {
      setActions([]); // the banner is optional; never break the case page
    }
  }, [caseId]);

  useEffect(() => {
    void load();
  }, [load]);

  const move = actions.find((a) => a.kind === "move" && (a.status === "executed" || a.status === "undone"));
  if (!move) return null;
  const restoring = actions.some(
    (a) => a.kind === "undo" && a.parent_id === move.id && (a.status === "issued" || a.status === "claimed"),
  );
  const when = new Date(move.undone_at ?? move.executed_at ?? move.issued_at ?? "").toLocaleString();

  if (move.status === "undone") {
    return (
      <Alert tone="success" title="Restored to the inbox">
        Cordon had moved this message to “{move.label}”; it was restored {when} and recorded as a false positive.
      </Alert>
    );
  }

  const undo = async () => {
    setBusy(true);
    try {
      const r = await undoMailboxAction(move.id);
      toast({ title: "Restoring", description: r.detail });
      await load();
    } catch (e) {
      toast({ title: "Undo failed", description: e instanceof Error ? e.message : undefined });
    } finally {
      setBusy(false);
    }
  };

  return (
    <Alert
      tone="warning"
      title={`Moved to “${move.label}” at ${when}`}
      action={
        restoring ? (
          <span className="text-xs">Restoring…</span>
        ) : (
          <Button size="sm" variant="secondary" loading={busy} onClick={undo}>
            Undo
          </Button>
        )
      }
    >
      Cordon took this out of the inbox automatically
      {move.gate ? ` (rules score ${move.gate.score}, floor ${move.gate.floor}; ${move.gate.checks.map((c) => c.label.toLowerCase()).join("; ")})` : ""}.
      Nothing was deleted.
    </Alert>
  );
}
