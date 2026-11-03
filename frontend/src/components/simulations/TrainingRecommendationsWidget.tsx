import { useEffect, useState } from "react";
import { getTrainingRecommendations } from "../../api/client";
import type { SimulationTrainingRecommendation } from "../../types/analysis";
import { RiskScoreBadge } from "./SimulationStatusBadge";
import {
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
} from "../ui";

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
    <Card padding="none" as="div">
      <CardHeader title="Training Recommendations" description="Generated automatically the moment an employee clicks or submits — tied to the exact lure they fell for." />
      {error && <ErrorState message={error} className="m-4" />}
      <TableContainer>
        <Table>
          <THead>
            <tr>
              <TH density="comfortable">Recipient</TH>
              <TH density="comfortable">Risk score</TH>
              <TH density="comfortable">Lure</TH>
              <TH density="comfortable">Recommendation</TH>
              <TH density="comfortable">Updated</TH>
            </tr>
          </THead>
          <TBody>
            {items.map((item) => (
              <tr key={item.recipient}>
                <TD density="comfortable" className="text-fg">{item.recipient}</TD>
                <TD density="comfortable">
                  <RiskScoreBadge score={item.risk_score} />
                </TD>
                <TD density="comfortable" className="text-fg-secondary">{item.template_name}</TD>
                <TD density="comfortable" className="text-fg-secondary">{item.recommendation}</TD>
                <TD density="comfortable" className="text-fg-secondary">{new Date(item.updated_at).toLocaleDateString()}</TD>
              </tr>
            ))}
            {!error && items.length === 0 && (
              <TableMessageRow colSpan={5}>
                <EmptyState variant="inline" title="No recommendations yet." />
              </TableMessageRow>
            )}
          </TBody>
        </Table>
      </TableContainer>
    </Card>
  );
}
