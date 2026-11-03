import { useEffect, useState } from "react";
import { getTargets } from "../../api/client";
import type { TargetSummary } from "../../types/analysis";
import {
  Badge,
  Card,
  EmptyState,
  ErrorState,
  TBody,
  TD,
  TH,
  THead,
  Table,
  TableContainer,
  TableMessageRow,
} from "../ui";

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
    <Card padding="none" as="div">
      <div className="border-b border-line bg-surface-panel px-6 py-3">
        <h3 className="text-base font-semibold text-fg">Repeat Targets</h3>
        {threshold !== null && (
          <p className="text-xs text-fg-secondary">
            Flagged for micro-training at {threshold}+ flagged attempts.
          </p>
        )}
      </div>
      {error && <ErrorState message={error} className="m-4" />}
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Recipient</TH>
              <TH density="comfortable">Hits</TH>
              <TH density="comfortable">Status</TH>
              <TH density="comfortable">Training Recommendation</TH>
            </tr>
          </THead>
          <TBody>
            {topTargets.map((target) => (
              <tr key={target.recipient}>
                <TD density="comfortable" className="text-fg">{target.recipient}</TD>
                <TD density="comfortable" className="text-fg-secondary">{target.hit_count}</TD>
                <TD density="comfortable">
                  {target.flagged_for_training ? (
                    <Badge tone="danger">Flagged</Badge>
                  ) : (
                    <Badge>Below threshold</Badge>
                  )}
                </TD>
                <TD density="comfortable" className="text-fg-secondary">{target.recommendation ?? "—"}</TD>
              </tr>
            ))}
            {!error && topTargets.length === 0 && (
              <TableMessageRow colSpan={4}>
                <EmptyState variant="inline" title="No repeat targets yet." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
