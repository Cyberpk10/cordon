import { useEffect, useState } from "react";
import { downloadAuditReport, generateAuditReport, getAuditEvidence } from "../../api/client";
import type { AuditEvidenceResponse, AuditFrameworkAlias } from "../../types/analysis";
import EvidenceTable from "./EvidenceTable";
import RecentReportsList from "./RecentReportsList";
import { Button, Card, ErrorState, Field, Input, LoadingState, Select } from "../ui";

const FRAMEWORK_OPTIONS: { value: AuditFrameworkAlias; label: string }[] = [
  { value: "mitre", label: "MITRE ATT&CK" },
  { value: "nist", label: "NIST CSF" },
  { value: "iso", label: "ISO 27001" },
  { value: "soc2", label: "SOC 2" },
];

export default function AuditView() {
  const [framework, setFramework] = useState<AuditFrameworkAlias>("mitre");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [evidence, setEvidence] = useState<AuditEvidenceResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generateError, setGenerateError] = useState<string | null>(null);
  const [reportsRefreshToken, setReportsRefreshToken] = useState(0);

  const periodParams = {
    dateFrom: dateFrom ? `${dateFrom}T00:00:00` : undefined,
    dateTo: dateTo ? `${dateTo}T23:59:59` : undefined,
  };

  useEffect(() => {
    let cancelled = false;
    setIsLoading(true);
    setError(null);

    getAuditEvidence({ framework, ...periodParams })
      .then((data) => {
        if (!cancelled) setEvidence(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load evidence.");
      })
      .finally(() => {
        if (!cancelled) setIsLoading(false);
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [framework, dateFrom, dateTo]);

  const handleGenerate = async () => {
    setIsGenerating(true);
    setGenerateError(null);
    try {
      const report = await generateAuditReport({ framework, ...periodParams });
      await downloadAuditReport(report.id, "pdf");
      setReportsRefreshToken((token) => token + 1);
    } catch (err) {
      setGenerateError(err instanceof Error ? err.message : "Failed to generate evidence pack.");
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-4 rounded-xl border border-line bg-surface-panel p-5 shadow-sm">
        <div>
          <h2 className="text-lg font-semibold text-fg">Audit Mode</h2>
          <p className="text-sm text-fg-secondary">
            {evidence
              ? `${evidence.framework_name} · ${new Date(evidence.period_start).toLocaleDateString()} – ${new Date(evidence.period_end).toLocaleDateString()}`
              : "Loading…"}
          </p>
        </div>
        <div className="flex flex-wrap gap-3">
          <Field label="Framework">
            <Select
              value={framework}
              onChange={(event) => setFramework(event.target.value as AuditFrameworkAlias)}
            >
              {FRAMEWORK_OPTIONS.map((option) => (
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

      {error && <ErrorState message={error} />}

      {isLoading && !evidence && <LoadingState label="Loading evidence…" />}

      {evidence && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <Card padding="md" as="div">
              <p className="text-sm font-semibold text-fg-secondary">Total Controls</p>
              <p className="mt-1 text-3xl font-semibold text-fg">{evidence.total_controls}</p>
            </Card>
            <Card padding="md" as="div">
              <p className="text-sm font-semibold text-fg-secondary">Operating</p>
              <p className="mt-1 text-3xl font-semibold text-success">{evidence.operating_controls}</p>
            </Card>
            <Card padding="md" as="div" className="flex flex-col justify-between">
              <p className="text-sm font-semibold text-fg-secondary">Evidence Pack</p>
              <Button
                variant="primary"
                className="mt-2"
                onClick={handleGenerate}
                loading={isGenerating}
                loadingText="Generating…"
              >
                Generate Evidence Pack
              </Button>
            </Card>
          </div>

          {generateError && <ErrorState message={generateError} />}

          <EvidenceTable controls={evidence.controls} />
          <RecentReportsList refreshToken={reportsRefreshToken} />
        </>
      )}
    </div>
  );
}
