import { useEffect, useState } from "react";
import { getMonitoringControls } from "../../api/client";
import type { ControlHealth, ControlHealthStatus } from "../../types/analysis";
import { ShieldQuestion } from "lucide-react";
import { Card, EmptyState, ErrorState, Select } from "../ui";

const STATUS_STYLES: Record<ControlHealthStatus, string> = {
  operating: "border-success/35 bg-success/10 text-success",
  degraded: "border-warning/35 bg-warning/10 text-warning",
  stale: "border-danger/35 bg-danger/10 text-danger",
  no_evidence: "border-line bg-surface-panel text-fg-secondary",
};

const STATUS_LABELS: Record<ControlHealthStatus, string> = {
  operating: "Operating",
  degraded: "Degraded",
  stale: "Stale",
  no_evidence: "No evidence",
};

const FRAMEWORKS = [
  { value: "", label: "All frameworks" },
  { value: "mitre_attack", label: "MITRE ATT&CK" },
  { value: "nist_csf", label: "NIST CSF" },
  { value: "iso_27001", label: "ISO 27001" },
  { value: "soc2", label: "SOC 2" },
];

function formatLastEvidence(value: string | null): string {
  if (!value) return "Never";
  return new Date(value).toLocaleDateString();
}

export default function ControlGrid() {
  const [items, setItems] = useState<ControlHealth[]>([]);
  const [framework, setFramework] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getMonitoringControls(framework || undefined)
      .then((data) => setItems(data.items))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load controls."));
  }, [framework]);

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-fg">Control health</h2>
        <Select
          value={framework}
          onChange={(e) => setFramework(e.target.value)}
          aria-label="Framework"
          className="w-48"
        >
          {FRAMEWORKS.map((fw) => (
            <option key={fw.value} value={fw.value}>
              {fw.label}
            </option>
          ))}
        </Select>
      </div>

      {error && <ErrorState message={error} className="mt-4" />}

      <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
        {items.map((c) => (
          <div
            key={`${c.framework_key}-${c.control_id}`}
            className={`rounded-control border p-3 ${STATUS_STYLES[c.status]}`}
          >
            <div className="text-xs font-semibold uppercase tracking-wide opacity-70">
              {c.framework_key}
            </div>
            <div className="mt-1 truncate text-sm font-semibold" title={c.control_name}>
              {c.control_id}
            </div>
            <div className="truncate text-xs opacity-80" title={c.control_name}>
              {c.control_name}
            </div>
            <div className="mt-2 flex items-center justify-between text-xs">
              <span className="rounded-full bg-surface-page/40 px-2 py-0.5 font-semibold">
                {STATUS_LABELS[c.status]}
              </span>
              <span className="opacity-70">{formatLastEvidence(c.last_evidence_at)}</span>
            </div>
          </div>
        ))}
        {items.length === 0 && !error && (
          <EmptyState icon={ShieldQuestion} title="No controls loaded yet." className="col-span-full" />
        )}
      </div>
    </Card>
  );
}
