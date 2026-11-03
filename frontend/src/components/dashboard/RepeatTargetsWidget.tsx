import { useEffect, useState } from "react";
import { getTargets } from "../../api/client";
import type { TargetSummary } from "../../types/analysis";

export default function RepeatTargetsWidget() {
  const [targets, setTargets] = useState<TargetSummary[]>([]);
  const [threshold, setThreshold] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getTargets()
      .then((data) => {
        if (cancelled) return;
        setTargets(data.targets);
        setThreshold(data.threshold);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load targets.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const topTargets = targets.slice(0, 10);

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Repeat Targets</h3>
        {threshold !== null && (
          <p className="text-xs text-fg-secondary">
            Flagged for micro-training at {threshold}+ flagged attempts.
          </p>
        )}
      </div>
      {error && <div className="p-4 text-sm text-danger">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
          <tr>
            <th className="px-6 py-3 font-semibold">Recipient</th>
            <th className="px-6 py-3 font-semibold">Hits</th>
            <th className="px-6 py-3 font-semibold">Status</th>
            <th className="px-6 py-3 font-semibold">Training Recommendation</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {topTargets.map((target) => (
            <tr key={target.recipient}>
              <td className="px-6 py-3 text-fg">{target.recipient}</td>
              <td className="px-6 py-3 text-fg-secondary">{target.hit_count}</td>
              <td className="px-6 py-3">
                {target.flagged_for_training ? (
                  <span className="rounded-full border border-danger/35 bg-danger/10 px-2.5 py-0.5 text-xs font-semibold text-danger">
                    Flagged
                  </span>
                ) : (
                  <span className="rounded-full border border-line-strong bg-surface-raised px-2.5 py-0.5 text-xs font-semibold text-fg-secondary">
                    Below threshold
                  </span>
                )}
              </td>
              <td className="px-6 py-3 text-fg-secondary">{target.recommendation ?? "—"}</td>
            </tr>
          ))}
          {topTargets.length === 0 && (
            <tr>
              <td colSpan={4} className="px-6 py-8 text-center text-fg-secondary">
                No repeat targets yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
