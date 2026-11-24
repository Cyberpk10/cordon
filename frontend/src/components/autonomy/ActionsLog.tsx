import { useEffect, useState } from "react";
import { Undo2 } from "lucide-react";
import { getAutonomyActions, reverseAutonomyAction } from "../../api/client";
import type { AutonomyActionLogEntry } from "../../types/analysis";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  Select,
  TBody,
  TD,
  TH,
  THead,
  Table,
  TableContainer,
  TableMessageRow,
  type BadgeTone,
} from "../ui";

const DECISION_TONE: Record<string, BadgeTone> = {
  auto_execute: "success",
  require_approval: "warning",
  skip: "neutral",
};

const STATUS_TONE: Record<string, BadgeTone> = {
  executed: "success",
  reversed: "neutral",
  pending_approval: "warning",
  skipped: "neutral",
  halted: "danger",
  shadow: "violet",
  above_tier: "neutral",
  approved: "accent",
  dismissed: "neutral",
  execution_failed: "danger",
};

export default function ActionsLog() {
  const [items, setItems] = useState<AutonomyActionLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [actionType, setActionType] = useState("");
  const [status, setStatus] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [undoingId, setUndoingId] = useState<string | null>(null);
  const pageSize = 20;

  const load = () => {
    getAutonomyActions({
      page,
      pageSize,
      actionType: actionType || undefined,
      status: status || undefined,
    })
      .then((data) => {
        setItems(data.items);
        setTotal(data.total);
      })
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load actions."));
  };

  useEffect(load, [page, actionType, status]);

  const handleUndo = async (id: string) => {
    setUndoingId(id);
    setError(null);
    try {
      await reverseAutonomyAction(id);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to reverse action.");
    } finally {
      setUndoingId(null);
    }
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap gap-4">
        <Field label="Action type">
          <Select
            value={actionType}
            onChange={(e) => {
              setPage(1);
              setActionType(e.target.value);
            }}
            className="w-52"
          >
            <option value="">All</option>
            <option value="LABEL_CASE">Tag the case</option>
            <option value="SET_TRIAGE">Set status and priority</option>
            <option value="NOTIFY">Notify the team</option>
            <option value="OPEN_INVESTIGATION">Open an investigation</option>
            <option value="WATCHLIST_SENDER">Watch the sender</option>
            <option value="BLOCKLIST_DOMAIN">Blocklist the domain</option>
            <option value="WATCHLIST_IP">Watch the sending IP</option>
            <option value="GROUP_CAMPAIGN">Group into a campaign</option>
            <option value="ESCALATE_PRIORITY">Escalate priority</option>
            <option value="RECOMMEND_MAILBOX_REMEDIATION">Recommend mailbox remediation</option>
            <option value="QUARANTINE_EMAIL">Quarantine email</option>
            <option value="FLAG_ACCOUNT_FOR_REVIEW">Flag account for review</option>
            <option value="DISABLE_SESSION">Disable session</option>
            <option value="BLOCK_SENDER_DOMAIN">Block sender domain</option>
          </Select>
        </Field>
        <Field label="Status">
          <Select
            value={status}
            onChange={(e) => {
              setPage(1);
              setStatus(e.target.value);
            }}
            className="w-52"
          >
            <option value="">All</option>
            <option value="executed">Executed</option>
            <option value="shadow">Shadow (would have)</option>
            <option value="reversed">Reversed</option>
            <option value="pending_approval">Pending approval</option>
            <option value="above_tier">Above tier</option>
            <option value="approved">Approved</option>
            <option value="dismissed">Dismissed</option>
            <option value="skipped">Skipped</option>
            <option value="halted">Halted</option>
          </Select>
        </Field>
      </div>

      {error && <ErrorState message={error} />}

      <Card padding="none" as="div" className="overflow-x-auto">
        <TableContainer>
          <Table>
            <THead>
              <tr>
                <TH>When</TH>
                <TH>Action</TH>
                <TH>Target</TH>
                <TH>Why</TH>
                <TH>Tier / rule</TH>
                <TH>Undo path</TH>
                <TH>Confidence</TH>
                <TH>Controls</TH>
                <TH>Decision</TH>
                <TH>Status</TH>
                <TH></TH>
              </tr>
            </THead>
            <TBody>
              {items.map((item) => (
                <tr key={item.id}>
                  <TD className="text-fg-secondary">
                    {new Date(item.created_at).toLocaleString()}
                  </TD>
                  <TD className="text-fg">
                    {(item.result?.description as string | undefined) ?? item.action_type}
                    {item.mode === "shadow" && (
                      <Badge size="sm" tone="violet" className="ml-1.5">
                        shadow
                      </Badge>
                    )}
                  </TD>
                  <TD className="text-fg-secondary">{item.target}</TD>
                  <TD className="text-fg-secondary">{item.trigger_finding_id}</TD>
                  <TD className="whitespace-nowrap text-fg-secondary">
                    {item.tier ? `${item.tier} · ` : ""}
                    <span className="font-mono text-xs">{item.rule_id ?? "—"}</span>
                  </TD>
                  <TD className="text-xs text-fg-secondary">{item.undo?.description ?? (item.reversible ? "Reverse" : "None")}</TD>
                  <TD className="text-fg-secondary">{item.confidence.toFixed(2)}</TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {Object.entries(item.mapped_controls).flatMap(([fw, refs]) =>
                        refs.map((ref) => (
                          <Badge key={`${fw}-${ref.control_id}`} size="sm" title={ref.control_name}>
                            {fw}: {ref.control_id}
                            <span className="sr-only"> — {ref.control_name}</span>
                          </Badge>
                        ))
                      )}
                    </div>
                  </TD>
                  <TD>
                    <Badge tone={DECISION_TONE[item.decision] ?? "neutral"} caps>
                      {item.decision}
                    </Badge>
                  </TD>
                  <TD>
                    <Badge tone={STATUS_TONE[item.status] ?? "neutral"} caps>
                      {item.status}
                    </Badge>
                  </TD>
                  <TD>
                    {item.status === "executed" && item.reversible && (
                      <Button
                        size="sm"
                        icon={Undo2}
                        onClick={() => handleUndo(item.id)}
                        loading={undoingId === item.id}
                        loadingText="Undoing…"
                      >
                        Undo
                      </Button>
                    )}
                  </TD>
                </tr>
              ))}
              {!error && items.length === 0 && (
                <TableMessageRow colSpan={11}>
                  <EmptyState variant="inline" title="No autonomy actions recorded yet." />
                </TableMessageRow>
              )}
            </TBody>
          </Table>
        </TableContainer>
      </Card>

      <div className="flex items-center justify-between text-sm text-fg-secondary">
        <span>
          {total} action{total === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-3">
          <Button size="sm" onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page <= 1}>
            Previous
          </Button>
          <span>
            Page {page} of {totalPages}
          </span>
          <Button
            size="sm"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}
