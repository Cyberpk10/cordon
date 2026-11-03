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
    <Card padding="none" as="div">
      <CardHeader title="Control Drift" description="Top active drift alerts across all frameworks." />
      {error && <ErrorState message={error} className="m-4" />}
      <ul className="divide-y divide-line">
        {topAlerts.map((alert, i) => (
          <li
            key={`${alert.framework_key}-${alert.control_id}-${alert.type}-${i}`}
            className="flex items-center justify-between gap-3 px-6 py-3"
          >
            <span className="truncate text-sm text-fg">
              {alert.control_id ? `${alert.control_id} — ${alert.control_name}` : alert.control_name}
            </span>
            <Badge tone={SEVERITY_TONE[alert.severity]} caps className="shrink-0">
              {alert.severity}
            </Badge>
          </li>
        ))}
        {topAlerts.length === 0 && !error && (
          <li>
            <EmptyState variant="inline" icon={ShieldCheck} title="No active drift alerts." />
          </li>
        )}
      </ul>
    </Card>
  );
}
