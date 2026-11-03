import { useEffect, useState } from "react";
import { getHumanRiskSummary } from "../../api/client";
import type { HumanRiskSummaryResponse } from "../../types/analysis";
import ClickRateChart from "./ClickRateChart";
import DepartmentBreakdownTable from "./DepartmentBreakdownTable";
import LureEffectivenessTable from "./LureEffectivenessTable";
import RiskiestUsersTable from "./RiskiestUsersTable";
import TrainingRecommendationsWidget from "./TrainingRecommendationsWidget";
import { ErrorState, Field, Input, LoadingState } from "../ui";

export default function HumanRiskView() {
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [summary, setSummary] = useState<HumanRiskSummaryResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getHumanRiskSummary({
      dateFrom: dateFrom ? `${dateFrom}T00:00:00` : undefined,
      dateTo: dateTo ? `${dateTo}T23:59:59` : undefined,
    })
      .then((data) => {
        if (!cancelled) setSummary(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load Human Risk data.");
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [dateFrom, dateTo]);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4 rounded-xl border border-line bg-surface-panel p-5 shadow-sm">
        <div>
          <h2 className="text-lg font-semibold text-fg">Human Risk</h2>
          <p className="text-sm text-fg-secondary">
            {summary
              ? `${new Date(summary.period_start).toLocaleDateString()} – ${new Date(summary.period_end).toLocaleDateString()}`
              : "Loading period…"}
          </p>
        </div>
        <div className="flex gap-3">
          <Field label="From">
            <Input
              type="date"
              value={dateFrom}
              onChange={(event) => setDateFrom(event.target.value)}
            />
          </Field>
          <Field label="To">
            <Input
              type="date"
              value={dateTo}
              onChange={(event) => setDateTo(event.target.value)}
            />
          </Field>
        </div>
      </div>

      {error && <ErrorState message={error} />}

      {isLoading && !summary && <LoadingState label="Loading Human Risk data…" />}

      {summary && (
        <>
          <RiskiestUsersTable users={summary.riskiest_users} />
          <ClickRateChart periods={summary.click_rate_over_time} />
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <LureEffectivenessTable lures={summary.lure_effectiveness} />
            <DepartmentBreakdownTable departments={summary.department_breakdown} />
          </div>
          <TrainingRecommendationsWidget />
        </>
      )}
    </div>
  );
}
