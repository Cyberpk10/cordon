import { useEffect, useState } from "react";
import { getCases } from "../api/client";
import type { CaseSummary, MessageChannel, Verdict } from "../types/analysis";
import ChannelBadge from "./ChannelBadge";
import VerdictBadge from "./VerdictBadge";

const PAGE_SIZE = 20;

const VERDICT_OPTIONS: { label: string; value: Verdict | "" }[] = [
  { label: "All verdicts", value: "" },
  { label: "Safe", value: "safe" },
  { label: "Suspicious", value: "suspicious" },
  { label: "Malicious", value: "malicious" },
];

const CHANNEL_OPTIONS: { label: string; value: MessageChannel | "" }[] = [
  { label: "All channels", value: "" },
  { label: "Email", value: "email" },
  { label: "Slack", value: "slack" },
  { label: "Teams", value: "teams" },
];

interface CasesTableProps {
  onSelectCase: (id: string) => void;
  refreshToken: number;
}

export default function CasesTable({ onSelectCase, refreshToken }: CasesTableProps) {
  const [items, setItems] = useState<CaseSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState<Verdict | "">("");
  const [channel, setChannel] = useState<MessageChannel | "">("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getCases({
      page,
      pageSize: PAGE_SIZE,
      verdict,
      channel,
      dateFrom: dateFrom ? `${dateFrom}T00:00:00` : undefined,
      dateTo: dateTo ? `${dateTo}T23:59:59` : undefined,
    })
      .then((response) => {
        if (cancelled) return;
        setItems(response.items);
        setTotal(response.total);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load cases.");
      })
      .finally(() => {
        if (cancelled) return;
        setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page, verdict, channel, dateFrom, dateTo, refreshToken]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-4">
        <label className="flex flex-col gap-1 text-sm text-fg-secondary">
          Verdict
          <select
            value={verdict}
            onChange={(event) => {
              setPage(1);
              setVerdict(event.target.value as Verdict | "");
            }}
            className="rounded-lg border border-line-strong bg-surface-card px-3 py-1.5 text-sm text-fg"
          >
            {VERDICT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm text-fg-secondary">
          Channel
          <select
            value={channel}
            onChange={(event) => {
              setPage(1);
              setChannel(event.target.value as MessageChannel | "");
            }}
            className="rounded-lg border border-line-strong bg-surface-card px-3 py-1.5 text-sm text-fg"
          >
            {CHANNEL_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-sm text-fg-secondary">
          From
          <input
            type="date"
            value={dateFrom}
            onChange={(event) => {
              setPage(1);
              setDateFrom(event.target.value);
            }}
            className="rounded-lg border border-line-strong bg-surface-card px-3 py-1.5 text-sm text-fg"
          />
        </label>
        <label className="flex flex-col gap-1 text-sm text-fg-secondary">
          To
          <input
            type="date"
            value={dateTo}
            onChange={(event) => {
              setPage(1);
              setDateTo(event.target.value);
            }}
            className="rounded-lg border border-line-strong bg-surface-card px-3 py-1.5 text-sm text-fg"
          />
        </label>
      </div>

      {error && (
        <div className="rounded-lg border border-danger/35 bg-danger/10 p-4 text-sm text-danger">
          {error}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
            <tr>
              <th className="px-4 py-3 font-semibold">Verdict / Score</th>
              <th className="px-4 py-3 font-semibold">Channel</th>
              <th className="px-4 py-3 font-semibold">Sender</th>
              <th className="px-4 py-3 font-semibold">Subject</th>
              <th className="px-4 py-3 font-semibold">Date</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {items.map((item) => (
              <tr
                key={item.id}
                onClick={() => onSelectCase(item.id)}
                className="cursor-pointer transition hover:bg-surface-raised"
              >
                <td className="px-4 py-3">
                  <VerdictBadge verdict={item.verdict} score={item.score} />
                </td>
                <td className="px-4 py-3">
                  <ChannelBadge channel={item.channel} />
                </td>
                <td className="px-4 py-3 text-fg-secondary">{item.from_addr ?? "—"}</td>
                <td className="px-4 py-3 text-fg-secondary">{item.subject ?? item.filename}</td>
                <td className="px-4 py-3 text-fg-secondary">
                  {new Date(item.created_at).toLocaleString()}
                </td>
              </tr>
            ))}
            {!isLoading && items.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-fg-secondary">
                  No cases match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-fg-secondary">
        <span>
          {total} case{total === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1 || isLoading}
            className="rounded-lg border border-line-strong px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Previous
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages || isLoading}
            className="rounded-lg border border-line-strong px-3 py-1.5 disabled:cursor-not-allowed disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  );
}
