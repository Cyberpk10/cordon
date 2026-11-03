import { useEffect, useState } from "react";
import { getHumanRiskSummary } from "../../api/client";
import type { HumanRiskSummaryResponse } from "../../types/analysis";
import ClickRateChart from "./ClickRateChart";
import DepartmentBreakdownTable from "./DepartmentBreakdownTable";
import LureEffectivenessTable from "./LureEffectivenessTable";
import RiskiestUsersTable from "./RiskiestUsersTable";
import TrainingRecommendationsWidget from "./TrainingRecommendationsWidget";
import { DateRangeFilter, ErrorState, LoadingState } from "../ui";
import PageActions, { PageContext } from "../shell/PageActions";
import { formatPeriod } from "../../format";

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
      <PageActions>
        <DateRangeFilter
          label="Human risk period"
          from={dateFrom}
          to={dateTo}
          onFromChange={setDateFrom}
          onToChange={setDateTo}
        />
      </PageActions>
      {summary && <PageContext>{formatPeriod(summary.period_start, summary.period_end)}</PageContext>}

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
