import { useEffect, useState } from "react";
import { getThreatLevels } from "../../api/client";
import type { ThreatLevelEntry } from "../../types/analysis";

const LEVEL_STYLES: Record<string, string> = {
  normal: "border-line-strong bg-surface-raised text-fg-secondary",
  elevated: "border-warning/35 bg-warning/10 text-warning",
  attack_forming: "border-caution/35 bg-caution/10 text-caution",
  active_incident: "border-danger/35 bg-danger/10 text-danger",
};

const TREND_ARROW: Record<string, string> = {
  rising: "↑",
  steady: "→",
  falling: "↓",
};

export default function WatchlistWidget() {
  const [actors, setActors] = useState<ThreatLevelEntry[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getThreatLevels()
      .then((data) => {
        if (cancelled) return;
        setActors(data.actors);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load the watchlist.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const rising = actors
    .filter((a) => a.trend === "rising")
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Watchlist</h3>
        <p className="text-xs text-fg-secondary">
          Actors whose threat level is rising — precursor signals accumulating before any incident.
        </p>
      </div>
      {error && <div className="p-4 text-sm text-danger">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
          <tr>
            <th className="px-6 py-3 font-semibold">Actor</th>
            <th className="px-6 py-3 font-semibold">Score</th>
            <th className="px-6 py-3 font-semibold">Level</th>
            <th className="px-6 py-3 font-semibold">Trend</th>
            <th className="px-6 py-3 font-semibold">Top contributing signal</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rising.map((entry) => {
            const topSignal = [...entry.contributing_signals].sort((a, b) => b.stage - a.stage)[0];
            return (
              <tr key={entry.actor}>
                <td className="px-6 py-3 text-fg">{entry.actor}</td>
                <td className="px-6 py-3 text-fg-secondary">{entry.score.toFixed(1)}</td>
                <td className="px-6 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-semibold ${LEVEL_STYLES[entry.level] ?? LEVEL_STYLES.normal}`}
                  >
                    {entry.level}
                  </span>
                </td>
                <td className="px-6 py-3 text-fg-secondary">{TREND_ARROW[entry.trend] ?? entry.trend}</td>
                <td className="px-6 py-3 text-fg-secondary">{topSignal?.description ?? "—"}</td>
              </tr>
            );
          })}
          {rising.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-fg-secondary">
                No actors currently rising.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
