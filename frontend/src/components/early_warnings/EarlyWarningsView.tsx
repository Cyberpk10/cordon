import { useEffect, useState } from "react";
import { acknowledgeEarlyWarning, getEarlyWarnings } from "../../api/client";
import type { EarlyWarningAlertEntry } from "../../types/analysis";

const BAND_STYLES: Record<string, string> = {
  normal: "border-slate-300 bg-slate-100 text-slate-600",
  elevated: "border-amber-300 bg-amber-100 text-amber-800",
  attack_forming: "border-orange-400 bg-orange-100 text-orange-800",
  active_incident: "border-red-400 bg-red-100 text-red-800",
};

function BandBadge({ band }: { band: string }) {
  return (
    <span
      className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${BAND_STYLES[band] ?? BAND_STYLES.normal}`}
    >
      {band.replace("_", " ")}
    </span>
  );
}

export default function EarlyWarningsView() {
  const [alerts, setAlerts] = useState<EarlyWarningAlertEntry[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [ackingId, setAckingId] = useState<string | null>(null);

  const load = () => {
    setIsLoading(true);
    getEarlyWarnings()
      .then((data) => setAlerts(data.alerts))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load early warnings."))
      .finally(() => setIsLoading(false));
  };

  useEffect(() => {
    load();
  }, []);

  const handleAck = async (id: string) => {
    setAckingId(id);
    try {
      await acknowledgeEarlyWarning(id);
      setAlerts((prev) => prev.filter((a) => a.id !== id));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to acknowledge the alert.");
    } finally {
      setAckingId(null);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h2 className="text-lg font-semibold text-slate-900">Early Warnings</h2>
        <p className="text-sm text-slate-600">
          Actors with multiple corroborating precursor signals at different kill-chain stages —
          an attack appears to be forming, before any incident exists. Nothing here executes any
          action automatically.
        </p>
      </div>

      {error && (
        <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">{error}</div>
      )}

      {isLoading && <p className="text-sm text-slate-500">Loading early warnings…</p>}

      {!isLoading && alerts.length === 0 && (
        <div className="rounded-xl border border-slate-200 bg-white p-8 text-center text-sm text-slate-500 shadow-sm">
          No actors currently showing signs of a forming attack.
        </div>
      )}

      <div className="flex flex-col gap-4">
        {alerts.map((alert) => (
          <div key={alert.id} className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 bg-slate-900 px-6 py-3">
              <div className="flex items-center gap-3">
                <h3 className="text-base font-semibold text-white">{alert.actor}</h3>
                <BandBadge band={alert.band} />
                <span className="text-sm text-slate-300">score {alert.score.toFixed(1)}</span>
              </div>
              <button
                type="button"
                onClick={() => handleAck(alert.id)}
                disabled={ackingId === alert.id}
                className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 transition hover:bg-slate-100 disabled:opacity-50"
              >
                {ackingId === alert.id ? "Acknowledging…" : "Acknowledge"}
              </button>
            </div>

            <div className="grid grid-cols-1 gap-4 p-6 md:grid-cols-2">
              <div>
                <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Reasoning timeline
                </h4>
                <p className="text-sm text-slate-700">{alert.timeline_summary}</p>
                <ul className="mt-3 space-y-1 text-xs text-slate-500">
                  {alert.signal_timeline.map((signal, i) => (
                    <li key={i}>
                      stage {signal.stage} · {signal.type} · {new Date(signal.timestamp).toLocaleString()}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Recommended pre-emptive actions
                </h4>
                <ul className="space-y-2">
                  {alert.recommended_actions.map((action) => (
                    <li key={action.step_id} className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                      <p className="text-sm font-medium text-slate-800">{action.title}</p>
                      <p className="text-xs text-slate-600">{action.description}</p>
                    </li>
                  ))}
                  {alert.recommended_actions.length === 0 && (
                    <li className="text-xs text-slate-500">No specific recommendation.</li>
                  )}
                </ul>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
