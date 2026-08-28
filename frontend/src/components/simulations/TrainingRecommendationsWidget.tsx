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
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
        <h3 className="text-base font-semibold text-white">Training Recommendations</h3>
        <p className="text-xs text-slate-300">
          Generated automatically the moment an employee clicks or submits — tied to the exact lure they fell for.
        </p>
      </div>
      {error && <div className="p-4 text-sm text-red-700">{error}</div>}
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-6 py-3 font-medium">Recipient</th>
            <th className="px-6 py-3 font-medium">Risk score</th>
            <th className="px-6 py-3 font-medium">Lure</th>
            <th className="px-6 py-3 font-medium">Recommendation</th>
            <th className="px-6 py-3 font-medium">Updated</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {items.map((item) => (
            <tr key={item.recipient}>
              <td className="px-6 py-3 text-slate-800">{item.recipient}</td>
              <td className="px-6 py-3">
                <RiskScoreBadge score={item.risk_score} />
              </td>
              <td className="px-6 py-3 text-slate-600">{item.template_name}</td>
              <td className="px-6 py-3 text-slate-600">{item.recommendation}</td>
              <td className="px-6 py-3 text-slate-500">{new Date(item.updated_at).toLocaleDateString()}</td>
            </tr>
          ))}
          {items.length === 0 && (
            <tr>
              <td colSpan={5} className="px-6 py-8 text-center text-slate-500">
                No recommendations yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}
