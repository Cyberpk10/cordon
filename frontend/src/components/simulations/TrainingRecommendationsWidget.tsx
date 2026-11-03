import { useEffect, useState } from "react";
import { getTrainingRecommendations } from "../../api/client";
import type { SimulationTrainingRecommendation } from "../../types/analysis";
import { RiskScoreBadge } from "./SimulationStatusBadge";

export default function TrainingRecommendationsWidget() {
  const [items, setItems] = useState<SimulationTrainingRecommendation[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    getTrainingRecommendations()
      .then((data) => {
        if (!cancelled) setItems(data.items);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load recommendations.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface-card shadow-sm">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Training Recommendations</h3>
        <p className="text-xs text-fg-secondary">
          Generated automatically the moment an employee clicks or submits — tied to the exact lure they fell for.
        </p>
      </div>
      {error && <div className="p-4 text-sm text-danger">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-line bg-surface-panel text-xs uppercase tracking-wide text-fg-secondary">
          <tr>
            <th className="px-6 py-3 font-semibold">Recipient</th>
            <th className="px-6 py-3 font-semibold">Risk score</th>
            <th className="px-6 py-3 font-semibold">Lure</th>
            <th className="px-6 py-3 font-semibold">Recommendation</th>
            <th className="px-6 py-3 font-semibold">Updated</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {items.map((item) => (
            <tr key={item.recipient}>
              <td className="px-6 py-3 text-fg">{item.recipient}</td>
              <td className="px-6 py-3">
                <RiskScoreBadge score={item.risk_score} />
              </td>
              <td className="px-6 py-3 text-fg-secondary">{item.template_name}</td>
              <td className="px-6 py-3 text-fg-secondary">{item.recommendation}</td>
              <td className="px-6 py-3 text-fg-secondary">{new Date(item.updated_at).toLocaleDateString()}</td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-fg-secondary">
                No recommendations yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
