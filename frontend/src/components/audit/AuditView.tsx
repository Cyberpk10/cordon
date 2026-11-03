import { useEffect, useState } from "react";
import { FileDown } from "lucide-react";
import { downloadAuditReport, generateAuditReport, getAuditEvidence } from "../../api/client";
import type { AuditEvidenceResponse, AuditFrameworkAlias } from "../../types/analysis";
import EvidenceTable from "./EvidenceTable";
import RecentReportsList from "./RecentReportsList";
import { Button, Card, DateRangeFilter, ErrorState, LoadingState, Select } from "../ui";
import PageActions, { PageContext } from "../shell/PageActions";
import { formatPeriod } from "../../format";

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
      <PageActions>
        <Select
          controlSize="sm"
          aria-label="Framework"
          value={framework}
          onChange={(event) => setFramework(event.target.value as AuditFrameworkAlias)}
          className="w-full sm:w-40"
        >
          {FRAMEWORK_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>
              {option.label}
            </option>
          ))}
        </Select>
        <DateRangeFilter
          label="Evidence period"
          from={dateFrom}
          to={dateTo}
          onFromChange={setDateFrom}
          onToChange={setDateTo}
        />
        <Button
          variant="primary"
          size="sm"
          icon={FileDown}
          onClick={handleGenerate}
          loading={isGenerating}
          loadingText="Generating…"
        >
          Generate Evidence Pack
        </Button>
      </PageActions>
      {evidence && (
        <PageContext>
          {evidence.framework_name} · {formatPeriod(evidence.period_start, evidence.period_end)}
        </PageContext>
      )}

      {error && <ErrorState message={error} />}

      {isLoading && !evidence && <LoadingState label="Loading evidence…" />}

      {evidence && (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Card padding="md" as="div">
              <p className="text-sm font-semibold text-fg-secondary">Total Controls</p>
              <p className="mt-1 text-3xl font-semibold text-fg">{evidence.total_controls}</p>
            </Card>
            <Card padding="md" as="div">
              <p className="text-sm font-semibold text-fg-secondary">Operating</p>
              <p className="mt-1 text-3xl font-semibold text-success">{evidence.operating_controls}</p>
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
