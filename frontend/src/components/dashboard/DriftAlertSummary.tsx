import { useEffect, useState } from "react";
import { getMonitoringDrift } from "../../api/client";
import type { DriftAlert, DriftAlertSeverity } from "../../types/analysis";

const SEVERITY_STYLES: Record<DriftAlertSeverity, string> = {
  medium: "bg-warning/10 text-warning border-warning/35",
  high: "bg-caution/10 text-caution border-caution/35",
  critical: "bg-danger/10 text-danger border-danger/35",
};

export default function DriftAlertSummary() {
  const [alerts, setAlerts] = useState<DriftAlert[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getMonitoringDrift()
      .then((data) => {
        if (cancelled) return;
        setAlerts(data.items);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load drift alerts.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const topAlerts = alerts.slice(0, 5);

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Control Drift</h3>
        <p className="text-xs text-fg-secondary">Top active drift alerts across all frameworks.</p>
      </div>
      {error && <div className="p-4 text-sm text-danger">{error}</div>}
      <ul className="divide-y divide-line">
        {topAlerts.map((alert, i) => (
          <li
            key={`${alert.framework_key}-${alert.control_id}-${alert.type}-${i}`}
            className="flex items-center justify-between gap-3 px-6 py-3"
          >
            <span className="truncate text-sm text-fg">
              {alert.control_id ? `${alert.control_id} — ${alert.control_name}` : alert.control_name}
            </span>
            <span
              className={`shrink-0 rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[alert.severity]}`}
            >
              {alert.severity}
            </span>
          </li>
        ))}
        {topAlerts.length === 0 && !error && (
          <li className="px-6 py-8 text-center text-sm text-fg-secondary">No active drift alerts.</li>
        )}
      </ul>
    </div>
  );
}
