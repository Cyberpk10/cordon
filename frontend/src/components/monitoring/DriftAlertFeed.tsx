import { useEffect, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { getMonitoringDrift } from "../../api/client";
import type { DriftAlert, DriftAlertSeverity } from "../../types/analysis";
import { Badge, Card, CardHeader, EmptyState, ErrorState, type BadgeTone } from "../ui";

const SEVERITY_TONE: Record<DriftAlertSeverity, BadgeTone> = {
  medium: "warning",
  high: "caution",
  critical: "danger",
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
    <Card padding="none">
      <CardHeader
        level={2}
        title="Drift alerts"
        description="Controls that have gone quiet, authentication pass-rates falling, or framework coverage dropping."
      />

      {error && <ErrorState message={error} className="m-6" />}

      <div className="divide-y divide-line">
        {items.map((alert, i) => (
          <div
            key={`${alert.framework_key}-${alert.control_id}-${alert.type}-${i}`}
            className="flex flex-wrap items-start justify-between gap-3 px-6 py-4"
          >
            <div>
              <div className="flex items-center gap-2">
                <Badge tone={SEVERITY_TONE[alert.severity]} caps>
                  {alert.severity}
                </Badge>
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
          <EmptyState icon={ShieldCheck} title="No active drift alerts." description="Every monitored control is reporting as expected." />
        )}
      </div>
    </Card>
  );
}
