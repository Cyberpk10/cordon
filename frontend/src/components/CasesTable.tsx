import { useEffect, useState } from "react";
import { getCases } from "../api/client";
import type { CaseSummary, MessageChannel, Verdict } from "../types/analysis";
import ChannelBadge from "./ChannelBadge";
import VerdictBadge from "./VerdictBadge";
import { ChevronLeft, ChevronRight, FolderOpen } from "lucide-react";
import {
  Button,
  Card,
  EmptyState,
  ErrorState,
  Field,
  Input,
  LoadingState,
  Select,
  Table,
  TableContainer,
  TableMessageRow,
  TBody,
  TD,
  TH,
  THead,
  TR,
} from "./ui";

const PAGE_SIZE = 20;

const VERDICT_OPTIONS: { label: string; value: Verdict | "" }[] = [
  { label: "All verdicts", value: "" },
  { label: "Safe", value: "safe" },
  { label: "Suspicious", value: "suspicious" },
  { label: "Malicious", value: "malicious" },
];

const CHANNEL_OPTIONS: { label: string; value: MessageChannel | "" }[] = [
  { label: "All channels", value: "" },
  { label: "Email", value: "email" },
  { label: "Slack", value: "slack" },
  { label: "Teams", value: "teams" },
];

interface CasesTableProps {
  onSelectCase: (id: string) => void;
  refreshToken: number;
}

export default function CasesTable({ onSelectCase, refreshToken }: CasesTableProps) {
  const [items, setItems] = useState<CaseSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [verdict, setVerdict] = useState<Verdict | "">("");
  const [channel, setChannel] = useState<MessageChannel | "">("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getCases({
      page,
      pageSize: PAGE_SIZE,
      verdict,
      channel,
      dateFrom: dateFrom ? `${dateFrom}T00:00:00` : undefined,
      dateTo: dateTo ? `${dateTo}T23:59:59` : undefined,
    })
      .then((response) => {
        if (cancelled) return;
        setItems(response.items);
        setTotal(response.total);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load cases.");
      })
      .finally(() => {
        if (cancelled) return;
        setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [page, verdict, channel, dateFrom, dateTo, refreshToken]);

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
            className="w-40"
          >
            {VERDICT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Channel">
          <Select
            value={channel}
            onChange={(event) => {
              setPage(1);
              setChannel(event.target.value as MessageChannel | "");
            }}
            className="w-40"
          >
            {CHANNEL_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="From">
          <Input
            type="date"
            value={dateFrom}
            onChange={(event) => {
              setPage(1);
              setDateFrom(event.target.value);
            }}
          />
        </Field>
        <Field label="To">
          <Input
            type="date"
            value={dateTo}
            onChange={(event) => {
              setPage(1);
              setDateTo(event.target.value);
            }}
          />
        </Field>
      </div>

      {error && <ErrorState message={error} />}

      <Card padding="none">
        <TableContainer>
          <Table>
            <THead>
              <tr>
                <TH>Verdict / Score</TH>
                <TH>Channel</TH>
                <TH>Sender</TH>
                <TH>Subject</TH>
                <TH>Date</TH>
              </tr>
            </THead>
            <TBody>
              {isLoading && items.length === 0 && (
                <TableMessageRow colSpan={5}>
                  <LoadingState label="Loading cases…" lines={4} />
                </TableMessageRow>
              )}
              {items.map((item) => (
                <TR
                  key={item.id}
                  onActivate={() => onSelectCase(item.id)}
                  aria-label={`Open case: ${item.subject ?? item.filename}`}
                >
                  <TD>
                    <VerdictBadge verdict={item.verdict} score={item.score} />
                  </TD>
                  <TD>
                    <ChannelBadge channel={item.channel} />
                  </TD>
                  <TD className="whitespace-nowrap text-fg-secondary">{item.from_addr ?? "—"}</TD>
                  <TD className="min-w-[16rem] text-fg-secondary">{item.subject ?? item.filename}</TD>
                  <TD className="whitespace-nowrap text-fg-secondary">
                    {new Date(item.created_at).toLocaleString()}
                  </TD>
                </TR>
              ))}
              {!error && !isLoading && items.length === 0 && (
                <TableMessageRow colSpan={5}>
                  <EmptyState
                    icon={FolderOpen}
                    title="No cases match these filters."
                    description="Try widening the date range or clearing the verdict and channel filters."
                  />
                </TableMessageRow>
              )}
            </TBody>
          </Table>
        </TableContainer>
      </Card>

      <div className="flex items-center justify-between text-sm text-fg-secondary">
        <span>
          {total} case{total === 1 ? "" : "s"}
        </span>
        <div className="flex items-center gap-3">
          <Button
            size="sm"
            icon={ChevronLeft}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page <= 1 || isLoading}
          >
            Previous
          </Button>
          <span aria-live="polite">
            Page {page} of {totalPages}
          </span>
          <Button
            size="sm"
            icon={ChevronRight}
            iconPosition="end"
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
