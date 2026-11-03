import { useEffect, useState } from "react";
import { getIncidents } from "../../api/client";
import { useInterval } from "../../hooks/useInterval";
import type { IncidentSummary, Verdict } from "../../types/analysis";
import VerdictBadge from "../VerdictBadge";
import {
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  Select,
  TBody,
  TD,
  TH,
  THead,
  Table,
  TableContainer,
  TableMessageRow,
} from "../ui";

const PAGE_SIZE = 20;
// Dev-friendly live refresh so newly-raised incidents show up on their own — see
// frontend/src/hooks/useInterval.ts.
const POLL_INTERVAL_MS = 5000;

const VERDICT_OPTIONS: { label: string; value: Verdict | "" }[] = [
  { label: "All verdicts", value: "" },
  { label: "Suspicious", value: "suspicious" },
  { label: "Malicious", value: "malicious" },
];

interface IncidentsTableProps {
  onSelectIncident: (id: string) => void;
  refreshToken: number;
}

export default function IncidentsTable({ onSelectIncident, refreshToken }: IncidentsTableProps) {
  const [items, setItems] = useState<IncidentSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState<Verdict | "">("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pollTick, setPollTick] = useState(0);

  useInterval(() => setPollTick((tick) => tick + 1), POLL_INTERVAL_MS);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getIncidents({ page, pageSize: PAGE_SIZE, verdict })
      .then((response) => {
        if (cancelled) return;
        setItems(response.items);
        setTotal(response.total);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load incidents.");
      })
      .finally(() => {
        if (cancelled) return;
        setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page, verdict, refreshToken, pollTick]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-end gap-4">
        <Field label="Verdict">
          <Select
            value={verdict}
            onChange={(event) => {
              setPage(1);
              setVerdict(event.target.value as Verdict | "");
            }}
          >
            {VERDICT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </Field>
      </div>

      {error && <ErrorState message={error} />}

      <Card padding="none" as="div">
        <TableContainer>
          <Table>
            <THead>
              <tr>
                <TH>Risk</TH>
                <TH>Actor</TH>
                <TH>Detection Types</TH>
                <TH>Time</TH>
              </tr>
            </THead>
            <TBody>
              {items.map((item) => (
                <tr
                  key={item.id}
                  onClick={() => onSelectIncident(item.id)}
                  className="cursor-pointer transition hover:bg-surface-raised"
                >
                  <TD>
                    <VerdictBadge verdict={item.verdict} score={item.score} compact />
                  </TD>
                  <TD className="text-fg-secondary">{item.actor}</TD>
                  <TD>
                    <div className="flex flex-wrap gap-1">
                      {item.detection_types.map((type) => (
                        <Badge key={type} size="sm">
                          {type}
                        </Badge>
                      ))}
                    </div>
                  </TD>
                  <TD className="text-fg-secondary">
                    {new Date(item.created_at).toLocaleString()}
                  </TD>
                </tr>
              ))}
              {!error && !isLoading && items.length === 0 && (
                <TableMessageRow colSpan={4}>
                  <EmptyState variant="inline" title="No incidents match these filters." />
                </TableMessageRow>
              )}
            </TBody>
          </Table>
        </TableContainer>
      </Card>

      <div className="flex items-center justify-between text-sm text-fg-secondary">
        <span>
          {total} incident{total === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-3">
          <Button
            size="sm"
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1 || isLoading}
          >
            Previous
          </Button>
          <span>
            Page {page} of {totalPages}
          </span>
          <Button
            size="sm"
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages || isLoading}
          >
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}
