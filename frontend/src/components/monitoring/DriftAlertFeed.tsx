import { useEffect, useState } from "react";
import { getMonitoringDrift } from "../../api/client";
import type { DriftAlert, DriftAlertSeverity } from "../../types/analysis";

const SEVERITY_STYLES: Record<DriftAlertSeverity, string> = {
  medium: "bg-warning/10 text-warning border-warning/35",
  high: "bg-caution/10 text-caution border-caution/35",
  critical: "bg-danger/10 text-danger border-danger/35",
};

const TYPE_LABELS: Record<DriftAlert["type"], string> = {
  went_quiet: "Went quiet",
  auth_pass_rate_drop: "Auth pass-rate drop",
  coverage_drop: "Coverage drop",
};

export default function DriftAlertFeed() {
  const [items, setItems] = useState<DriftAlert[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getMonitoringDrift()
      .then((data) => setItems(data.items))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load drift alerts."));
  }, []);

  return (
    <section className="rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line px-6 py-4">
        <h2 className="text-lg font-semibold text-fg">Drift alerts</h2>
        <p className="mt-0.5 text-sm text-fg-secondary">
          Controls that have gone quiet, authentication pass-rates falling, or framework
          coverage dropping.
        </p>
      </div>

      {error && (
        <div className="m-6 rounded-lg border border-danger/35 bg-danger/10 p-4 text-sm text-danger">
          {error}
        </div>
      )}

      <div className="divide-y divide-line">
        {items.map((alert, i) => (
          <div
            key={`${alert.framework_key}-${alert.control_id}-${alert.type}-${i}`}
            className="flex flex-wrap items-start justify-between gap-3 px-6 py-4"
          >
            <div>
              <div className="flex items-center gap-2">
                <span
                  className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${SEVERITY_STYLES[alert.severity]}`}
                >
                  {alert.severity}
                </span>
                <span className="text-sm font-semibold text-fg">
                  {alert.control_id ? `${alert.control_id} — ${alert.control_name}` : alert.control_name}
                </span>
              </div>
              <p className="mt-1 text-sm text-fg-secondary">{alert.detail}</p>
              <p className="mt-1 text-xs text-fg-muted">
                {alert.framework_key} · {TYPE_LABELS[alert.type]} · since{" "}
                {new Date(alert.since).toLocaleDateString()}
              </p>
            </div>
          </div>
        ))}
        {items.length === 0 && !error && (
          <div className="px-6 py-8 text-center text-sm text-fg-secondary">
            No active drift alerts.
          </div>
        )}
      </div>
    </section>
  );
}
