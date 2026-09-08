import { useEffect, useState } from "react";
import { getEarlyWarnings } from "../../api/client";
import type { EarlyWarningAlertEntry } from "../../types/analysis";

export default function EarlyWarningBanner() {
  const [alerts, setAlerts] = useState<EarlyWarningAlertEntry[]>([]);

  useEffect(() => {
    let cancelled = false;
    getEarlyWarnings()
      .then((data) => {
        if (!cancelled) setAlerts(data.alerts);
      })
      .catch(() => {
        // Non-critical widget — a failed fetch here just means no banner, not an error state.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  if (alerts.length === 0) {
    return null;
  }

  return (
    <div className="flex items-center gap-3 rounded-xl border border-orange-400 bg-orange-50 px-5 py-3 text-sm text-orange-900 shadow-sm">
      <span className="text-lg">⚠</span>
      <p>
        <strong>{alerts.length}</strong> actor{alerts.length === 1 ? "" : "s"} showing signs of an
        attack forming — multiple corroborating precursor signals, before any incident. See the
        Early Warnings tab.
      </p>
    </div>
  );
}
