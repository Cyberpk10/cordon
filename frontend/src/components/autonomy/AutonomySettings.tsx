import { useCallback, useEffect, useState } from "react";
import { Eye, OctagonX, Power, Save, ShieldCheck, Trash2 } from "lucide-react";
import {
  getAutonomyPolicy,
  getCordonLists,
  getShadowSummary,
  putAutonomyPolicy,
  removeCordonListEntry,
  setKillSwitch,
} from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import type { AutonomyLevel, AutonomyPolicy, CordonListEntry, ShadowSummary } from "../../types/analysis";
import {
  Alert,
  Badge,
  Button,
  Card,
  ErrorState,
  Field,
  Input,
  LoadingState,
  Table,
  TableContainer,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Textarea,
  useConfirm,
  useToast,
} from "../ui";

const TIERS: { tier: AutonomyLevel; label: string; description: string }[] = [
  { tier: "L0", label: "L0 · Observe", description: "Analyze and record only. Every action becomes a recommendation for a person." },
  { tier: "L1", label: "L1 · Flag", description: "Tag the case, set its status and priority, notify the team, open an investigation." },
  {
    tier: "L2",
    label: "L2 · Auto-triage",
    description: "L1, plus add the sender, domain or IP to Cordon's watchlist/blocklist, group campaigns, escalate priority.",
  },
  {
    tier: "L3",
    label: "L3 · Recommend remediation",
    description: "L2, plus queue concrete mailbox actions (\"quarantine these 3\") for a person to approve and carry out.",
  },
];

const ACTION_LABEL: Record<string, string> = {
  LABEL_CASE: "Tag the case",
  SET_TRIAGE: "Set status and priority",
  NOTIFY: "Notify the team",
  OPEN_INVESTIGATION: "Open an investigation",
  WATCHLIST_SENDER: "Watch the sender",
  BLOCKLIST_DOMAIN: "Blocklist the domain",
  WATCHLIST_IP: "Watch the sending IP",
  GROUP_CAMPAIGN: "Group into a campaign",
  ESCALATE_PRIORITY: "Escalate to critical",
  RECOMMEND_MAILBOX_REMEDIATION: "Recommend mailbox remediation",
};

export default function AutonomySettings() {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";
  const [policy, setPolicy] = useState<AutonomyPolicy | null>(null);
  const [summary, setSummary] = useState<ShadowSummary | null>(null);
  const [lists, setLists] = useState<CordonListEntry[] | null>(null);
  const [exclusionsText, setExclusionsText] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const toast = useToast();
  const confirm = useConfirm();

  const load = useCallback(() => {
    getAutonomyPolicy()
      .then((data) => {
        setPolicy(data);
        setExclusionsText(data.exclusions.join("\n"));
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load policy."));
    getShadowSummary().then(setSummary).catch(() => setSummary(null));
    getCordonLists().then(setLists).catch(() => setLists([]));
  }, []);

  useEffect(load, [load]);

  const save = async (patch: Partial<AutonomyPolicy>, okMessage: string) => {
    if (!policy) return;
    const next = { ...policy, ...patch };
    setBusy("save");
    setError(null);
    try {
      const saved = await putAutonomyPolicy({
        tier: next.tier,
        shadow_mode: next.shadow_mode,
        exclusions: exclusionsText.split("\n").map((s) => s.trim()).filter(Boolean),
        blast_radius_limit: next.blast_radius_limit,
        blast_radius_window_minutes: next.blast_radius_window_minutes,
      });
      setPolicy(saved);
      setExclusionsText(saved.exclusions.join("\n"));
      toast({ title: okMessage });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to save.");
    } finally {
      setBusy(null);
    }
  };

  const toggleShadow = async () => {
    if (!policy) return;
    if (policy.shadow_mode) {
      const ok = await confirm({
        title: `Let Cordon act at ${policy.tier}?`,
        description:
          "Cordon will start performing actions at or below this tier on new flagged mail. Every action is reversible and only changes Cordon's own records; nothing touches a mailbox.",
        confirmLabel: "Go active",
      });
      if (!ok) return;
    }
    await save({ shadow_mode: !policy.shadow_mode }, policy.shadow_mode ? "Autonomy is active" : "Back in shadow mode");
  };

  const toggleKill = async () => {
    if (!policy) return;
    const turningOn = !policy.kill_switch;
    if (turningOn) {
      const ok = await confirm({
        title: "Stop all autonomy?",
        description: "Cordon stops acting immediately and pending approvals are halted. You can turn it back on at any time.",
        confirmLabel: "Stop everything",
        tone: "danger",
      });
      if (!ok) return;
    }
    setBusy("kill");
    setError(null);
    try {
      const res = await setKillSwitch(turningOn);
      setPolicy({ ...policy, kill_switch: res.kill_switch, halted_at: res.halted_at });
      toast({
        tone: turningOn ? "warning" : "success",
        title: turningOn ? "Autonomy stopped" : "Autonomy resumed",
        description: turningOn ? `${res.halted_pending_count} pending approval(s) halted.` : undefined,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to change the kill switch.");
    } finally {
      setBusy(null);
    }
  };

  const removeEntry = async (entry: CordonListEntry) => {
    setBusy(entry.id);
    try {
      await removeCordonListEntry(entry.id);
      setLists((cur) => (cur ?? []).filter((e) => e.id !== entry.id));
      toast({ title: `Removed ${entry.value} from the ${entry.list_name}list` });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to remove entry.");
    } finally {
      setBusy(null);
    }
  };

  if (!policy) {
    return <Card as="div">{error ? <ErrorState message={error} /> : <LoadingState label="Loading policy…" />}</Card>;
  }

  const fpRate =
    summary && summary.cases > 0 ? Math.round((summary.cases_later_labeled_safe / summary.cases) * 100) : null;

  return (
    <div className="flex flex-col gap-6">
      {!isAdmin && <Alert tone="info">Only admins can change autonomy settings.</Alert>}
      {error && <ErrorState message={error} />}

      <Card tone="danger" padding="md">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="flex items-center gap-2 text-base font-semibold text-danger">
              <OctagonX aria-hidden="true" className="h-4 w-4" />
              Kill switch {policy.kill_switch && <Badge tone="danger">On: autonomy stopped</Badge>}
            </h2>
            <p className="mt-1 text-sm text-fg-secondary">
              Stops every autonomous action instantly and halts pending approvals.
              {policy.halted_at && (
                <span className="block text-xs">Last stopped: {new Date(policy.halted_at).toLocaleString()}</span>
              )}
            </p>
          </div>
          <Button
            variant={policy.kill_switch ? "secondary" : "danger"}
            icon={Power}
            onClick={toggleKill}
            loading={busy === "kill"}
            disabled={!isAdmin}
          >
            {policy.kill_switch ? "Resume autonomy" : "Stop all autonomy"}
          </Button>
        </div>
      </Card>

      <Card padding="md" tone={policy.shadow_mode ? "default" : "default"}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="max-w-2xl">
            <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
              <Eye aria-hidden="true" className="h-4 w-4 text-violet" />
              Shadow mode
              <Badge tone={policy.shadow_mode ? "violet" : "success"}>{policy.shadow_mode ? "On" : "Off: acting"}</Badge>
            </h2>
            <p className="mt-1 text-sm text-fg-secondary">
              {policy.shadow_mode
                ? "Nothing is being done. Cordon records what it would have done at each tier so you can check its judgement on real mail first."
                : `Cordon is acting on new flagged mail at ${policy.tier} and below. Every action can be undone from the case.`}
            </p>
          </div>
          <Button variant="secondary" onClick={toggleShadow} loading={busy === "save"} disabled={!isAdmin}>
            {policy.shadow_mode ? "Go active" : "Return to shadow"}
          </Button>
        </div>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-fg">Autonomy tier</h2>
        <p className="mt-1 text-sm text-fg-secondary">
          The ceiling. Cordon performs only actions at or below it; anything above shows up on the case as a
          recommendation for a person. Email content can never change the tier or the action.
        </p>
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2">
          {TIERS.map((t) => (
            <label
              key={t.tier}
              className={`cursor-pointer rounded-control border p-4 transition-colors duration-150 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-accent ${
                policy.tier === t.tier ? "border-accent bg-accent/10" : "border-line hover:border-line-strong"
              }`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name="autonomy-tier"
                  checked={policy.tier === t.tier}
                  disabled={!isAdmin}
                  onChange={() => setPolicy({ ...policy, tier: t.tier })}
                />
                <span className="font-semibold text-fg">{t.label}</span>
              </div>
              <p className="mt-1 text-xs text-fg-secondary">{t.description}</p>
            </label>
          ))}
        </div>
        <p className="mt-3 flex items-start gap-2 text-xs text-fg-muted">
          <ShieldCheck aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          Cordon never quarantines, moves or deletes real email at any tier. That needs mailbox write access and is
          a later step.
        </p>
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-fg">What Cordon would have done (last 30 days)</h2>
        {summary && summary.rows.length > 0 ? (
          <>
            <p className="mt-1 text-sm text-fg-secondary">
              {summary.cases} case(s) in shadow mode.{" "}
              {fpRate !== null && (
                <>
                  An analyst later labelled <strong>{summary.cases_later_labeled_safe}</strong> of them safe ({fpRate}%),
                  the false-positive rate to watch before going active.
                </>
              )}
            </p>
            <TableContainer className="mt-3">
              <Table>
                <THead>
                  <tr>
                    <TH>Action</TH>
                    <TH>Tier</TH>
                    <TH>Would have</TH>
                    <TH>Within your tier</TH>
                    <TH>Later labelled safe</TH>
                  </tr>
                </THead>
                <TBody>
                  {summary.rows.map((r) => (
                    <TR key={r.action_type + r.tier}>
                      <TD>{ACTION_LABEL[r.action_type] ?? r.action_type}</TD>
                      <TD>{r.tier}</TD>
                      <TD>{r.would_have}</TD>
                      <TD>{r.within_tier}</TD>
                      <TD>{r.later_labeled_safe}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </TableContainer>
          </>
        ) : (
          <p className="mt-1 text-sm text-fg-secondary">No shadow decisions yet. They appear as flagged mail arrives.</p>
        )}
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-fg">Cordon watchlist and blocklist</h2>
        <p className="mt-1 text-sm text-fg-secondary">
          Inside Cordon only. A blocklisted sender raises the score of their future mail; a watched one adds a note.
          Removing an entry undoes it.
        </p>
        {lists && lists.length > 0 ? (
          <TableContainer className="mt-3">
            <Table>
              <THead>
                <tr>
                  <TH>Value</TH>
                  <TH>List</TH>
                  <TH>Added</TH>
                  <TH>
                    <span className="sr-only">Remove</span>
                  </TH>
                </tr>
              </THead>
              <TBody>
                {lists.map((e) => (
                  <TR key={e.id}>
                    <TD className="font-mono text-xs">{e.value}</TD>
                    <TD>
                      <Badge size="sm" tone={e.list_name === "block" ? "danger" : "warning"}>
                        {e.list_name === "block" ? "Blocklist" : "Watchlist"} · {e.kind}
                      </Badge>
                    </TD>
                    <TD className="text-xs text-fg-secondary">
                      {new Date(e.created_at).toLocaleDateString()} by {e.added_by}
                    </TD>
                    <TD>
                      <Button
                        size="sm"
                        variant="ghost"
                        icon={Trash2}
                        loading={busy === e.id}
                        onClick={() => removeEntry(e)}
                        aria-label={`Remove ${e.value}`}
                      >
                        Remove
                      </Button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </TableContainer>
        ) : (
          <p className="mt-3 text-sm text-fg-muted">Empty.</p>
        )}
      </Card>

      <Card>
        <h2 className="text-base font-semibold text-fg">Protected identities</h2>
        <p className="mt-1 text-sm text-fg-secondary">
          Senders, domains or IPs (one per line) Cordon never lists or proposes mailbox action for without a person.
        </p>
        <Textarea
          value={exclusionsText}
          onChange={(e) => setExclusionsText(e.target.value)}
          rows={3}
          disabled={!isAdmin}
          aria-label="Protected identities, one per line"
          placeholder="ceo@corp.com&#10;partner.example.com"
          className="mt-3 font-mono"
        />
        <h3 className="mt-5 text-sm font-semibold text-fg">Rate limit</h3>
        <p className="mt-1 text-sm text-fg-secondary">
          After this many automatic actions in the window, the rest wait for approval.
        </p>
        <div className="mt-3 flex gap-4">
          <Field label="Limit">
            <Input
              type="number"
              min={1}
              value={policy.blast_radius_limit}
              disabled={!isAdmin}
              onChange={(e) => setPolicy({ ...policy, blast_radius_limit: Number(e.target.value) })}
              className="w-24"
            />
          </Field>
          <Field label="Window (minutes)">
            <Input
              type="number"
              min={1}
              value={policy.blast_radius_window_minutes}
              disabled={!isAdmin}
              onChange={(e) => setPolicy({ ...policy, blast_radius_window_minutes: Number(e.target.value) })}
              className="w-24"
            />
          </Field>
        </div>
      </Card>

      {isAdmin && (
        <Button
          variant="primary"
          icon={Save}
          className="self-start"
          onClick={() => save({}, `Saved: tier ${policy.tier}`)}
          loading={busy === "save"}
          loadingText="Saving…"
        >
          Save tier and limits
        </Button>
      )}
    </div>
  );
}
