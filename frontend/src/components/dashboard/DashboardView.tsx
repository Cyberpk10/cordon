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
import { ErrorState, Field, Input, LoadingState } from "../ui";

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
      <div className="flex flex-wrap items-end justify-between gap-4 rounded-xl border border-line bg-surface-panel p-5 shadow-sm">
        <div>
          <h2 className="text-lg font-semibold text-fg">Threat &amp; Compliance Dashboard</h2>
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
