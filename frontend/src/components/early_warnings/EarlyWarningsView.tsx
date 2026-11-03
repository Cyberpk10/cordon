import { useEffect, useState } from "react";
import { CheckCheck, ShieldCheck } from "lucide-react";
import { acknowledgeEarlyWarning, getEarlyWarnings } from "../../api/client";
import type { EarlyWarningAlertEntry } from "../../types/analysis";
import { Badge, Button, Card, EmptyState, ErrorState, LoadingState, type BadgeTone } from "../ui";

const BAND_TONE: Record<string, BadgeTone> = {
  normal: "neutral",
  elevated: "warning",
  attack_forming: "caution",
  active_incident: "danger",
};

function BandBadge({ band }: { band: string }) {
  return (
    <Badge tone={BAND_TONE[band] ?? BAND_TONE.normal}>
      {band.replace("_", " ")}
    </Badge>
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
      <p className="max-w-3xl text-sm text-fg-secondary">
        Actors with multiple corroborating precursor signals at different kill-chain stages — an
        attack appears to be forming, before any incident exists. Nothing here executes any action
        automatically.
      </p>

      {error && <ErrorState message={error} />}

      {isLoading && <LoadingState label="Loading early warnings…" />}

      {!isLoading && alerts.length === 0 && (
        <Card padding="none" as="div">
          <EmptyState
            icon={ShieldCheck}
            title="No actors currently showing signs of a forming attack."
            description="Early warnings appear here when several precursor signals line up for the same account."
          />
        </Card>
      )}

      <div className="flex flex-col gap-4">
        {alerts.map((alert) => (
          <Card padding="none" as="div" key={alert.id}>
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-surface-panel px-6 py-3">
              <div className="flex items-center gap-3">
                <h3 className="text-base font-semibold text-fg">{alert.actor}</h3>
                <BandBadge band={alert.band} />
                <span className="text-sm text-fg-secondary">score {alert.score.toFixed(1)}</span>
              </div>
              <Button
                size="sm"
                icon={CheckCheck}
                onClick={() => handleAck(alert.id)}
                loading={ackingId === alert.id}
                loadingText="Acknowledging…"
              >
                Acknowledge
              </Button>
            </div>

            <div className="grid grid-cols-1 gap-4 p-6 md:grid-cols-2">
              <div>
                <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-secondary">
                  Reasoning timeline
                </h4>
                <p className="text-sm text-fg">{alert.timeline_summary}</p>
                <ul className="mt-3 space-y-1 text-xs text-fg-secondary">
                  {alert.signal_timeline.map((signal, i) => (
                    <li key={i}>
                      stage {signal.stage} · {signal.type} · {new Date(signal.timestamp).toLocaleString()}
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-secondary">
                  Recommended pre-emptive actions
                </h4>
                <ul className="space-y-2">
                  {alert.recommended_actions.map((action) => (
                    <li key={action.step_id} className="rounded-lg border border-line bg-surface-panel p-3">
                      <p className="text-sm font-semibold text-fg">{action.title}</p>
                      <p className="text-xs text-fg-secondary">{action.description}</p>
                    </li>
                  ))}
                  {alert.recommended_actions.length === 0 && (
                    <li className="text-xs text-fg-secondary">No specific recommendation.</li>
                  )}
                </ul>
              </div>
            </div>
          </Card>
        ))}
      </div>
    </div>
  );
}
