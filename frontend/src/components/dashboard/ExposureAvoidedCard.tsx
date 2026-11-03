import { useEffect, useState } from "react";
import { getFinancialRisk } from "../../api/client";
import type { FinancialRiskResponse, RiskAttackTypeBreakdown } from "../../types/analysis";
import { Button, Card, CardHeader, ErrorState, LoadingState, Table, TableContainer, TBody, TD, TH } from "../ui";

const ATTACK_TYPE_LABELS: Record<string, string> = {
  bec: "Business Email Compromise",
  credential_phishing: "Credential phishing",
  generic_phishing: "Generic phishing",
};

function formatUsd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    maximumFractionDigits: 0,
  }).format(value);
}

function BreakdownTable({ rows }: { rows: RiskAttackTypeBreakdown[] }) {
  return (
    <TableContainer>
      <Table>
        <thead className="text-xs uppercase tracking-wide text-fg-secondary">
          <tr>
            <TH density="none" className="py-1.5 pr-3">Attack type</TH>
            <TH density="none" className="py-1.5 pr-3">Count</TH>
            <TH density="none" className="py-1.5 pr-3">Avg loss</TH>
            <TH density="none" className="py-1.5">Subtotal</TH>
          </tr>
        </thead>
        <TBody>
          {rows.map((row) => (
            <tr key={row.attack_type}>
              <TD density="none" className="py-1.5 pr-3 text-fg">
                {ATTACK_TYPE_LABELS[row.attack_type] ?? row.attack_type}
              </TD>
              <TD density="none" className="py-1.5 pr-3 text-fg-secondary">{row.count}</TD>
              <TD density="none" className="py-1.5 pr-3 text-fg-secondary">{formatUsd(row.avg_loss_usd)}</TD>
              <TD density="none" className="py-1.5 font-semibold text-fg">{formatUsd(row.subtotal_usd)}</TD>
            </tr>
          ))}
        </TBody>
      </Table>
    </TableContainer>
  );
}

export default function ExposureAvoidedCard() {
  const [risk, setRisk] = useState<FinancialRiskResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showAssumptions, setShowAssumptions] = useState(false);

  useEffect(() => {
    let cancelled = false;

    getFinancialRisk()
      .then((data) => {
        if (!cancelled) setRisk(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load financial risk.");
      });

    return () => {
      cancelled = true;
    };
  }, []);

  if (error) {
    return <ErrorState message={error} />;
  }

  if (!risk) {
    return (
      <Card padding="md" as="div">
        <LoadingState label="Loading financial risk…" />
      </Card>
    );
  }

  return (
    <Card padding="none" as="div">
      <CardHeader
        title="Estimated Exposure Avoided This Quarter"
        description={`${new Date(risk.period_start).toLocaleDateString()} – ${new Date(risk.period_end).toLocaleDateString()}`}
        actions={
          <Button
            variant="link"
            aria-expanded={showAssumptions}
            aria-controls="exposure-assumptions"
            onClick={() => setShowAssumptions((v) => !v)}
          >
            {showAssumptions ? "Hide assumptions" : "View assumptions"}
          </Button>
        }
      />

      <div className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-2">
        <div>
          <p className="text-sm font-semibold text-fg-secondary">Exposure avoided</p>
          <p className="mt-1 text-3xl font-semibold text-success">
            {formatUsd(risk.exposure_avoided.total_usd)}
          </p>
          <div className="mt-3">
            <BreakdownTable rows={risk.exposure_avoided.by_attack_type} />
          </div>
        </div>

        <div>
          <p className="text-sm font-semibold text-fg-secondary">Residual risk</p>
          <p className="mt-1 text-3xl font-semibold text-danger">{formatUsd(risk.residual_risk.total_usd)}</p>
          <p className="mt-1 text-xs text-fg-secondary">
            {risk.residual_risk.false_negative_count} analyst-confirmed miss
            {risk.residual_risk.false_negative_count === 1 ? "" : "es"} this period.
          </p>
          <div className="mt-3">
            <BreakdownTable rows={risk.residual_risk.by_attack_type} />
          </div>
          <p className="mt-3 text-xs text-fg-muted">{risk.residual_risk.note}</p>
        </div>
      </div>

      {showAssumptions && (
        <div id="exposure-assumptions" className="border-t border-line bg-surface-panel px-6 py-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-fg-secondary">
            Assumptions used for this calculation
          </p>
          <TableContainer className="mt-2">
            <Table>
              <thead className="text-xs uppercase tracking-wide text-fg-secondary">
                <tr>
                  <TH density="none" className="py-1.5 pr-3">Assumption</TH>
                  <TH density="none" className="py-1.5 pr-3">Value</TH>
                  <TH density="none" className="py-1.5">Source</TH>
                </tr>
              </thead>
              <TBody>
                {Object.entries(risk.assumptions).map(([key, assumption]) => (
                  <tr key={key}>
                    <TD density="none" className="py-1.5 pr-3 font-mono text-xs text-fg">{key}</TD>
                    <TD density="none" className="py-1.5 pr-3 text-fg">{assumption.value}</TD>
                    <TD density="none" className="py-1.5 text-xs text-fg-secondary">{assumption.source}</TD>
                  </tr>
                ))}
              </TBody>
            </Table>
          </TableContainer>
        </div>
      )}
    </Card>
  );
}
