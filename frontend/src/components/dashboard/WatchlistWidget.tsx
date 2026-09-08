import { useEffect, useState } from "react";
import { getThreatLevels } from "../../api/client";
import type { ThreatLevelEntry } from "../../types/analysis";

const LEVEL_STYLES: Record<string, string> = {
  normal: "border-slate-300 bg-slate-100 text-slate-600",
  elevated: "border-amber-300 bg-amber-100 text-amber-800",
  attack_forming: "border-orange-300 bg-orange-100 text-orange-800",
  active_incident: "border-red-300 bg-red-100 text-red-800",
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
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Watchlist</h3>
        <p className="text-xs text-slate-300">
          Actors whose threat level is rising — precursor signals accumulating before any incident.
        </p>
      </div>
      {error && <div className="p-4 text-sm text-red-700">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-6 py-3 font-medium">Actor</th>
            <th className="px-6 py-3 font-medium">Score</th>
            <th className="px-6 py-3 font-medium">Level</th>
            <th className="px-6 py-3 font-medium">Trend</th>
            <th className="px-6 py-3 font-medium">Top contributing signal</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {rising.map((entry) => {
            const topSignal = [...entry.contributing_signals].sort((a, b) => b.stage - a.stage)[0];
            return (
              <tr key={entry.actor}>
                <td className="px-6 py-3 text-slate-800">{entry.actor}</td>
                <td className="px-6 py-3 text-slate-600">{entry.score.toFixed(1)}</td>
                <td className="px-6 py-3">
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${LEVEL_STYLES[entry.level] ?? LEVEL_STYLES.normal}`}
                  >
                    {entry.level}
                  </span>
                </td>
                <td className="px-6 py-3 text-slate-600">{TREND_ARROW[entry.trend] ?? entry.trend}</td>
                <td className="px-6 py-3 text-slate-600">{topSignal?.description ?? "—"}</td>
              </tr>
            );
          })}
          {rising.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                No actors currently rising.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
