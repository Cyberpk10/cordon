import type { KRIs } from "../../types/analysis";
import { Card, CardHeader, TBody, TD, Table, TableContainer } from "../ui";

function formatPct(value: number | null): string {
  return value === null ? "—" : `${value}%`;
}

interface KriTableProps {
  kris: KRIs;
}

export default function KriTable({ kris }: KriTableProps) {
  const rows = [
    {
      label: "Malicious Catch Rate",
      value: formatPct(kris.malicious_catch_rate_pct),
      note: `of ${kris.labeled_count} labeled case${kris.labeled_count === 1 ? "" : "s"}`,
    },
    {
      label: "False Positive Rate",
      value: formatPct(kris.false_positive_rate_pct),
      note: `of ${kris.labeled_count} labeled case${kris.labeled_count === 1 ? "" : "s"}`,
    },
    {
      label: "Mean Unlabeled Backlog",
      value:
        kris.mean_unlabeled_backlog_days === null ? "—" : `${kris.mean_unlabeled_backlog_days} days`,
      note: `${kris.unlabeled_count} unlabeled case${kris.unlabeled_count === 1 ? "" : "s"}`,
    },
  ];

  return (
    <Card padding="none" as="div">
      <CardHeader title="Key Risk Indicators" />
      <TableContainer>
        <Table>
          <TBody>
            {rows.map((row) => (
              <tr key={row.label}>
                <TD density="comfortable" className="font-semibold text-fg">{row.label}</TD>
                <TD density="comfortable" className="text-xl font-semibold text-fg">{row.value}</TD>
                <TD density="comfortable" className="text-xs text-fg-secondary">{row.note}</TD>
              </tr>
            ))}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
