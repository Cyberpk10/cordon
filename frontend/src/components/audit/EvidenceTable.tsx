import type { AuditControlEvidence } from "../../types/analysis";

interface EvidenceTableProps {
  controls: AuditControlEvidence[];
}

export default function EvidenceTable({ controls }: EvidenceTableProps) {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Per-Control Evidence</h3>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
            <tr>
              <th className="px-6 py-3 font-semibold">Control</th>
              <th className="px-6 py-3 font-semibold">Name</th>
              <th className="px-6 py-3 font-semibold">Detections</th>
              <th className="px-6 py-3 font-semibold">Status</th>
              <th className="px-6 py-3 font-semibold">Sample Cases</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {controls.map((control) => (
              <tr key={control.control_id}>
                <td className="px-6 py-3 font-mono text-xs text-fg">{control.control_id}</td>
                <td className="px-6 py-3 text-fg">{control.control_name}</td>
                <td className="px-6 py-3 text-fg-secondary">{control.detection_count}</td>
                <td className="px-6 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
                      control.operating
                        ? "border-success/35 bg-success/10 text-success"
                        : "border-line-strong bg-surface-raised text-fg-secondary"
                    }`}
                  >
                    {control.operating ? "Operating" : "No evidence"}
                  </span>
                </td>
                <td className="px-6 py-3">
                  <div className="flex flex-wrap gap-1">
                    {control.sample_cases.length === 0 && (
                      <span className="text-xs text-fg-muted">—</span>
                    )}
                    {control.sample_cases.map((sample) => (
                      <span
                        key={sample.id}
                        title={new Date(sample.created_at).toLocaleString()}
                        className="rounded border border-line bg-surface-panel px-1.5 py-0.5 text-xs text-fg-secondary"
                      >
                        {sample.id.slice(0, 8)} · {sample.verdict}
                      </span>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
            {controls.length === 0 && (
              <tr>
                <td colSpan={5} className="px-6 py-8 text-center text-fg-secondary">
                  No controls found for this framework.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
