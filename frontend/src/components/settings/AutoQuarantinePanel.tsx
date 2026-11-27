import { useCallback, useEffect, useMemo, useState } from "react";
import { ShieldAlert } from "lucide-react";
import {
  getMailboxCalibration,
  getMailboxRemediation,
  setMailboxRemediation,
  undoMailboxAction,
  updateMailboxRemediation,
  type CalibrationRow,
  type MailboxAction,
  type MailboxRemediationState,
} from "../../api/client";
import { Alert, Badge, Button, Card, Input, LoadingState, useConfirm, useToast } from "../ui";

function fmt(iso: string | null | undefined): string {
  return iso ? new Date(iso).toLocaleString() : "never";
}

/** Would this calibration row move at `floor`? Every non-floor check must pass, plus the score. */
function movesAt(row: CalibrationRow, floor: number): boolean {
  if (!row.checks || row.rule_score == null) return false;
  const others = Object.entries(row.checks).filter(([k]) => k !== "score_floor");
  return others.every(([, ok]) => ok) && row.rule_score >= floor;
}

function failedChecks(row: CalibrationRow): string[] {
  return Object.entries(row.checks ?? {})
    .filter(([, ok]) => !ok)
    .map(([k]) => k);
}

const CHECK_TEXT: Record<string, string> = {
  verdict_malicious: "not malicious",
  score_floor: "below floor",
  corroborated: "no corroboration",
  no_unresolved_c1: "trusted sender",
};

/** D7: the owner's live auto-quarantine for their own Gmail. Off until calibrated and enabled. */
export default function AutoQuarantinePanel() {
  const [state, setState] = useState<MailboxRemediationState | null>(null);
  const [rows, setRows] = useState<CalibrationRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [mailbox, setMailbox] = useState("");
  const [floor, setFloor] = useState(95);
  const [cap, setCap] = useState(5);
  const [notify, setNotify] = useState(false);
  const toast = useToast();
  const confirm = useConfirm();

  const apply = useCallback((s: MailboxRemediationState) => {
    setState(s);
    if (s.policy) {
      setMailbox(s.policy.mailbox_address ?? "");
      setFloor(s.policy.score_floor);
      setCap(s.policy.max_moves_per_hour);
      setNotify(s.policy.notify_email);
    }
  }, []);

  const load = useCallback(async () => {
    try {
      const [s, cal] = await Promise.all([getMailboxRemediation(), getMailboxCalibration()]);
      apply(s);
      setRows(cal.rows);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't load auto-quarantine settings.");
    }
  }, [apply]);

  useEffect(() => {
    void load();
  }, [load]);

  const run = async (fn: () => Promise<MailboxRemediationState | void>, ok?: string) => {
    setBusy(true);
    setError(null);
    try {
      const s = await fn();
      if (s) apply(s);
      if (ok) toast({ title: ok });
    } catch (e) {
      setError(e instanceof Error ? e.message : "That didn't work.");
    } finally {
      setBusy(false);
    }
  };

  const save = () =>
    run(
      () =>
        updateMailboxRemediation({
          mailbox_address: mailbox.trim() || undefined,
          score_floor: floor,
          max_moves_per_hour: cap,
          notify_email: notify,
        }),
      "Saved",
    );

  const enable = async () => {
    const ok = await confirm({
      title: "Turn on auto-quarantine?",
      description:
        "From now on Cordon moves qualifying messages out of your inbox into the quarantine label without asking. " +
        "Nothing is deleted, and every move can be undone.",
      confirmLabel: "Turn on",
    });
    if (ok) await run(() => setMailboxRemediation("enable"), "Auto-quarantine is live");
  };

  const undo = (a: MailboxAction) =>
    run(async () => {
      const r = await undoMailboxAction(a.id);
      toast({ title: "Restoring", description: r.detail });
      await load();
    });

  const calibrated = useMemo(() => {
    const moving = rows.filter((r) => movesAt(r, floor));
    const near = rows.filter((r) => r.verdict === "malicious" && !movesAt(r, floor) && failedChecks(r).length === 1);
    return { moving, near };
  }, [rows, floor]);

  if (!state) {
    return (
      <Card as="div">{error ? <Alert tone="danger">{error}</Alert> : <LoadingState label="Loading…" lines={3} />}</Card>
    );
  }

  const p = state.policy;
  const status = !p?.enabled ? "Off" : p.halted_at ? "Halted" : state.kill_switch ? "Kill switch on" : "Live";
  const statusTone = status === "Live" ? "success" : status === "Off" ? "neutral" : "danger";
  const pendingUndo = new Set(
    state.actions.filter((a) => a.kind === "undo" && (a.status === "issued" || a.status === "claimed")).map((a) => a.parent_id),
  );
  const moves = state.actions.filter((a) => a.kind === "move" && ["executed", "undone", "aborted", "failed"].includes(a.status));

  return (
    <Card as="div">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
          <ShieldAlert aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
          Auto-quarantine (your Gmail)
        </h2>
        <Badge tone={statusTone}>{status}</Badge>
      </div>
      <p className="mt-1 text-sm text-fg-secondary">
        The Gmail add-on moves a message to the “{state.server.label}” label only when it's malicious, scores at or above
        your floor, independent agents corroborate it, and no trusted-sender conflict is open. Nothing is deleted; every
        move can be undone. Your own mailbox only: any other account needs Google's CASA assessment first.
      </p>

      {error && (
        <Alert tone="danger" className="mt-4">
          {error}
        </Alert>
      )}
      {!state.server.secret_set && (
        <Alert tone="warning" className="mt-4">
          The server has no D7_DIRECTIVE_SECRET, so no message can be moved.
        </Alert>
      )}
      {p?.halted_at && (
        <Alert
          tone="danger"
          title={`Halted ${fmt(p.halted_at)} (${p.halt_reason})`}
          className="mt-4"
          action={
            <Button size="sm" variant="secondary" loading={busy} onClick={() => run(() => setMailboxRemediation("resume"), "Resumed")}>
              Resume
            </Button>
          }
        >
          More messages qualified within an hour than your cap allows, so Cordon stopped moving mail.
        </Alert>
      )}

      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <label className="flex flex-col gap-1 text-sm text-fg-secondary">
          Your Gmail address
          <Input value={mailbox} onChange={(e) => setMailbox(e.target.value)} placeholder="you@gmail.com" />
        </label>
        <div className="grid grid-cols-2 gap-3">
          <label className="flex flex-col gap-1 text-sm text-fg-secondary">
            Score floor
            <Input type="number" min={55} max={100} value={floor} onChange={(e) => setFloor(Number(e.target.value))} />
          </label>
          <label className="flex flex-col gap-1 text-sm text-fg-secondary">
            Max moves / hour
            <Input type="number" min={1} max={50} value={cap} onChange={(e) => setCap(Number(e.target.value))} />
          </label>
        </div>
      </div>
      <label className="mt-3 flex items-center gap-2 text-sm text-fg-secondary">
        <input type="checkbox" checked={notify} onChange={(e) => setNotify(e.target.checked)} />
        Also put a notice email in my inbox for every move
      </label>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Button variant="secondary" loading={busy} onClick={save}>
          Save
        </Button>
        {p?.enabled ? (
          <Button variant="secondary" tone="danger" loading={busy} onClick={() => run(() => setMailboxRemediation("disable"), "Turned off")}>
            Turn off
          </Button>
        ) : (
          <Button variant="primary" loading={busy} disabled={!p || p.enable_blockers.length > 0} onClick={enable}>
            Enable
          </Button>
        )}
        {p && <span className="text-xs text-fg-muted">{p.moves_last_hour} moved in the last hour</span>}
      </div>
      {p && !p.enabled && p.enable_blockers.length > 0 && (
        <ul className="mt-2 list-disc pl-5 text-xs text-fg-secondary">
          {p.enable_blockers.map((b) => (
            <li key={b}>{b}</li>
          ))}
        </ul>
      )}

      <section className="mt-5">
        <h3 className="text-sm font-semibold text-fg">Calibration</h3>
        {state.calibration ? (
          <p className="mt-1 text-sm text-fg-secondary">
            {state.calibration.status === "running" ? "In progress: " : `Run ${fmt(state.calibration.completed_at)}: `}
            {state.calibration.total} recent messages checked. At a floor of <b>{floor}</b>,{" "}
            <b>{calibrated.moving.length}</b> would have been moved
            {calibrated.near.length > 0 && <> and {calibrated.near.length} missed by one check</>}.
          </p>
        ) : (
          <p className="mt-1 text-sm text-fg-secondary">
            Not run yet. In the Apps Script editor, run <code>runCalibration</code>: it reads your last 30 days of mail
            (read-only) and reports here exactly which messages would be moved.
          </p>
        )}
        {(calibrated.moving.length > 0 || calibrated.near.length > 0) && (
          <ul className="mt-2 flex flex-col divide-y divide-line text-sm">
            {[...calibrated.moving, ...calibrated.near].map((r) => (
              <li key={r.gmail_message_id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5">
                <Badge size="sm" tone={movesAt(r, floor) ? "danger" : "neutral"}>
                  {movesAt(r, floor) ? "Would move" : `Missed: ${failedChecks(r).map((c) => CHECK_TEXT[c] ?? c).join(", ")}`}
                </Badge>
                <span className="min-w-0 flex-1 truncate text-fg">{r.subject || "(no subject)"}</span>
                <span className="text-xs text-fg-muted">
                  {r.from_addr} · {r.rule_score}/100{r.received_at ? ` · ${fmt(r.received_at)}` : ""}
                </span>
              </li>
            ))}
          </ul>
        )}
      </section>

      {moves.length > 0 && (
        <section className="mt-5">
          <h3 className="text-sm font-semibold text-fg">Recent moves</h3>
          <ul className="mt-2 flex flex-col divide-y divide-line text-sm">
            {moves.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-1.5">
                <Badge size="sm" tone={a.status === "executed" ? "danger" : a.status === "undone" ? "success" : "neutral"}>
                  {a.status === "executed" ? "In quarantine" : a.status === "undone" ? `Restored (${a.undo_source})` : a.status}
                </Badge>
                <span className="min-w-0 flex-1 truncate text-fg">{a.subject || "(no subject)"}</span>
                <span className="text-xs text-fg-muted">
                  {a.from_addr} · {fmt(a.executed_at ?? a.issued_at)}
                </span>
                {a.status === "executed" &&
                  (pendingUndo.has(a.id) ? (
                    <span className="text-xs text-fg-muted">Restoring…</span>
                  ) : (
                    <Button size="sm" variant="ghost" loading={busy} onClick={() => undo(a)}>
                      Undo
                    </Button>
                  ))}
              </li>
            ))}
          </ul>
        </section>
      )}

      {state.feedback.length > 0 && (
        <section className="mt-5">
          <h3 className="text-sm font-semibold text-fg">False positives by rule</h3>
          <p className="mt-1 text-xs text-fg-muted">From your undos. Recorded for review; never applied automatically.</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {state.feedback.map((f) => (
              <Badge key={f.indicator_id} size="sm" tone="warning">
                {f.indicator_id} · {f.false_positives}
              </Badge>
            ))}
          </div>
        </section>
      )}
    </Card>
  );
}
