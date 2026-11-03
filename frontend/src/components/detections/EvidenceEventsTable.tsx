import type { ActivityEvent } from "../../types/analysis";

interface EvidenceEventsTableProps {
  events: ActivityEvent[];
}

export default function EvidenceEventsTable({ events }: EvidenceEventsTableProps) {
  if (events.length === 0) {
    return (
      <p className="rounded-lg border border-line bg-surface-panel p-4 text-sm text-fg-secondary">
        No evidence events recorded.
      </p>
    );
  }

  return (
    <div className="overflow-x-auto rounded-xl border border-line bg-surface-card shadow-sm">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
          <tr>
            <th className="px-4 py-3 font-semibold">Time</th>
            <th className="px-4 py-3 font-semibold">Action</th>
            <th className="px-4 py-3 font-semibold">Source IP</th>
            <th className="px-4 py-3 font-semibold">Target</th>
            <th className="px-4 py-3 font-semibold">Bytes</th>
            <th className="px-4 py-3 font-semibold">Outcome</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {events.map((event) => (
            <tr key={event.id ?? event.timestamp}>
              <td className="px-4 py-3 text-fg-secondary">
                {new Date(event.timestamp).toLocaleString()}
              </td>
              <td className="px-4 py-3 text-fg">{event.action}</td>
              <td className="px-4 py-3 text-fg-secondary">{event.source_ip ?? "—"}</td>
              <td className="px-4 py-3 text-fg-secondary">{event.target ?? "—"}</td>
              <td className="px-4 py-3 text-fg-secondary">
                {event.bytes !== null ? event.bytes.toLocaleString() : "—"}
              </td>
              <td className="px-4 py-3 text-fg-secondary">{event.outcome ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
