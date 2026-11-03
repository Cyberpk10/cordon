import { useEffect, useState } from "react";
import { getDashboardSummary } from "../../api/client";
import { useInterval } from "../../hooks/useInterval";
import type { DashboardSummary } from "../../types/analysis";
import DriftAlertSummary from "./DriftAlertSummary";
import EarlyWarningBanner from "./EarlyWarningBanner";
import ExposureAvoidedCard from "./ExposureAvoidedCard";
import FrameworkCoveragePanel from "./FrameworkCoveragePanel";
import KpiCards from "./KpiCards";
import KriTable from "./KriTable";
import RepeatTargetsWidget from "./RepeatTargetsWidget";
import ThreatTrendChart from "./ThreatTrendChart";
import TopIndicatorsTable from "./TopIndicatorsTable";
import VerdictDonut from "./VerdictDonut";
import WatchlistWidget from "./WatchlistWidget";
import { DateRangeFilter, ErrorState, LoadingState } from "../ui";
import PageActions, { PageContext } from "../shell/PageActions";
import { formatPeriod } from "../../format";

// Dev-friendly live refresh so newly-created cases/incidents show up on their own — see
// frontend/src/hooks/useInterval.ts.
const POLL_INTERVAL_MS = 5000;

export default function DashboardView() {
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pollTick, setPollTick] = useState(0);

  useInterval(() => setPollTick((tick) => tick + 1), POLL_INTERVAL_MS);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getDashboardSummary({
      dateFrom: dateFrom ? `${dateFrom}T00:00:00` : undefined,
      dateTo: dateTo ? `${dateTo}T23:59:59` : undefined,
    })
      .then((data) => {
        if (!cancelled) setSummary(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load dashboard.");
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [dateFrom, dateTo, pollTick]);

  return (
    <div className="flex flex-col gap-6">
      <PageActions>
        <DateRangeFilter
          label="Dashboard period"
          from={dateFrom}
          to={dateTo}
          onFromChange={setDateFrom}
          onToChange={setDateTo}
        />
      </PageActions>
      {summary && <PageContext>{formatPeriod(summary.period_start, summary.period_end)}</PageContext>}

      <EarlyWarningBanner />

      {error && <ErrorState message={error} />}

      {isLoading && !summary && <LoadingState label="Loading dashboard…" />}

      {summary && (
        <>
          <KpiCards summary={summary} />

          <ExposureAvoidedCard />

          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <VerdictDonut verdictCounts={summary.verdict_counts} />
            <ThreatTrendChart monthlyTrend={summary.monthly_threat_trend} />
          </div>

          <TopIndicatorsTable indicators={summary.top_indicators} />
          <FrameworkCoveragePanel coverage={summary.framework_coverage} />
          <DriftAlertSummary />
          <WatchlistWidget />
          <RepeatTargetsWidget />
          <KriTable kris={summary.kris} />
        </>
      )}
    </div>
  );
}
