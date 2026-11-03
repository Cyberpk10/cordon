import { useEffect, useState } from "react";
import { getThreatLevels } from "../../api/client";
import type { ThreatLevelEntry } from "../../types/analysis";
import {
  Badge,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  TBody,
  TD,
  TH,
  THead,
  Table,
  TableContainer,
  TableMessageRow,
  type BadgeTone,
} from "../ui";

const LEVEL_TONE: Record<string, BadgeTone> = {
  normal: "neutral",
  elevated: "warning",
  attack_forming: "caution",
  active_incident: "danger",
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
    <Card padding="none" as="div">
      <CardHeader title="Watchlist" description="Actors whose threat level is rising — precursor signals accumulating before any incident." />
      {error && <ErrorState message={error} className="m-4" />}
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Actor</TH>
              <TH density="comfortable">Score</TH>
              <TH density="comfortable">Level</TH>
              <TH density="comfortable">Trend</TH>
              <TH density="comfortable">Top contributing signal</TH>
            </tr>
          </THead>
          <TBody>
            {rising.map((entry) => {
              const topSignal = [...entry.contributing_signals].sort((a, b) => b.stage - a.stage)[0];
              return (
                <tr key={entry.actor}>
                  <TD density="comfortable" className="text-fg">{entry.actor}</TD>
                  <TD density="comfortable" className="text-fg-secondary">{entry.score.toFixed(1)}</TD>
                  <TD density="comfortable">
                    <Badge tone={LEVEL_TONE[entry.level] ?? LEVEL_TONE.normal}>
                      {entry.level}
                    </Badge>
                  </TD>
                  <TD density="comfortable" className="text-fg-secondary">{TREND_ARROW[entry.trend] ?? entry.trend}</TD>
                  <TD density="comfortable" className="text-fg-secondary">{topSignal?.description ?? "—"}</TD>
                </tr>
              );
            })}
            {!error && rising.length === 0 && (
              <TableMessageRow colSpan={5}>
                <EmptyState variant="inline" title="No actors currently rising." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
