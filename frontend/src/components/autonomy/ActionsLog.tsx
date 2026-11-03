import { useEffect, useState } from "react";
import { getAutonomyActions, reverseAutonomyAction } from "../../api/client";
import type { AutonomyActionLogEntry } from "../../types/analysis";

const DECISION_STYLES: Record<string, string> = {
  auto_execute: "bg-success/10 text-success border-success/35",
  require_approval: "bg-warning/10 text-warning border-warning/35",
  skip: "bg-surface-raised text-fg-secondary border-line-strong",
};

const STATUS_STYLES: Record<string, string> = {
  executed: "bg-success/10 text-success border-success/35",
  reversed: "bg-surface-raised text-fg-secondary border-line-strong",
  pending_approval: "bg-warning/10 text-warning border-warning/35",
  skipped: "bg-surface-raised text-fg-secondary border-line-strong",
  halted: "bg-danger/10 text-danger border-danger/35",
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
        <label className="flex flex-col gap-1 text-sm text-fg-secondary">
          Action type
          <select
            value={actionType}
            onChange={(e) => {
              setPage(1);
              setActionType(e.target.value);
            }}
            className="rounded-lg border border-line-strong bg-surface-card px-3 py-1.5 text-sm"
          >
            <option value="">All</option>
            <option value="QUARANTINE_EMAIL">Quarantine email</option>
            <option value="FLAG_ACCOUNT_FOR_REVIEW">Flag account for review</option>
            <option value="DISABLE_SESSION">Disable session</option>
            <option value="BLOCK_SENDER_DOMAIN">Block sender domain</option>
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm text-fg-secondary">
          Status
          <select
            value={status}
            onChange={(e) => {
              setPage(1);
              setStatus(e.target.value);
            }}
            className="rounded-lg border border-line-strong bg-surface-card px-3 py-1.5 text-sm"
          >
            <option value="">All</option>
            <option value="executed">Executed</option>
            <option value="reversed">Reversed</option>
            <option value="pending_approval">Pending approval</option>
            <option value="skipped">Skipped</option>
            <option value="halted">Halted</option>
          </select>
        </label>
      </div>

      {error && (
        <div className="rounded-lg border border-danger/35 bg-danger/10 p-4 text-sm text-danger">{error}</div>
      )}

      <div className="overflow-x-auto rounded-xl border border-line bg-surface-card shadow-sm">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
            <tr>
              <th className="px-4 py-3 font-semibold">When</th>
              <th className="px-4 py-3 font-semibold">Action</th>
              <th className="px-4 py-3 font-semibold">Target</th>
              <th className="px-4 py-3 font-semibold">Why</th>
              <th className="px-4 py-3 font-semibold">Confidence</th>
              <th className="px-4 py-3 font-semibold">Controls</th>
              <th className="px-4 py-3 font-semibold">Decision</th>
              <th className="px-4 py-3 font-semibold">Status</th>
              <th className="px-4 py-3 font-semibold"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {items.map((item) => (
              <tr key={item.id}>
                <td className="px-4 py-3 text-fg-secondary">
                  {new Date(item.created_at).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-fg">{item.action_type}</td>
                <td className="px-4 py-3 text-fg-secondary">{item.target}</td>
                <td className="px-4 py-3 text-fg-secondary">{item.trigger_finding_id}</td>
                <td className="px-4 py-3 text-fg-secondary">{item.confidence.toFixed(2)}</td>
                <td className="px-4 py-3">
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(item.mapped_controls).flatMap(([fw, refs]) =>
                      refs.map((ref) => (
                        <span
                          key={`${fw}-${ref.control_id}`}
                          title={ref.control_name}
                          className="rounded border border-line bg-surface-panel px-1.5 py-0.5 text-xs text-fg-secondary"
                        >
                          {fw}: {ref.control_id}
                        </span>
                      ))
                    )}
                  </div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${DECISION_STYLES[item.decision]}`}
                  >
                    {item.decision}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${STATUS_STYLES[item.status]}`}
                  >
                    {item.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  {item.status === "executed" && item.reversible && (
                    <button
                      onClick={() => handleUndo(item.id)}
                      disabled={undoingId === item.id}
                      className="rounded-lg border border-line-strong px-3 py-1 text-xs font-semibold text-fg hover:bg-surface-raised disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      {undoingId === item.id ? "Undoing…" : "Undo"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr>
                <td colSpan={9} className="px-4 py-8 text-center text-fg-secondary">
                  No autonomy actions recorded yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-fg-secondary">
        <span>
          {total} action{total === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1}
            className="rounded-lg border border-line-strong px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Previous
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="rounded-lg border border-line-strong px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
