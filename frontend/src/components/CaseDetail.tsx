import { useEffect, useState } from "react";
import { deleteCase, getCase, submitLabel } from "../api/client";
import type { CaseDetail as CaseDetailType, Verdict } from "../types/analysis";
import AiAuthoredFlag from "./AiAuthoredFlag";
import AIAnalystSummary from "./AIAnalystSummary";
import FrameworkMappingPanel from "./FrameworkMappingPanel";
import IndicatorList from "./IndicatorList";
import InvestigationPanel from "./InvestigationPanel";
import ResponsePlaybookPanel from "./ResponsePlaybookPanel";
import VerdictBadge from "./VerdictBadge";
import { ArrowLeft, Trash2 } from "lucide-react";
import { Button, Card, ErrorState, Field, Input, LoadingState, SectionHeading, Select, useToast } from "./ui";

interface CaseDetailProps {
  caseId: string;
  onBack: () => void;
  onDeleted: () => void;
}

export default function CaseDetail({ caseId, onBack, onDeleted }: CaseDetailProps) {
  const [caseData, setCaseData] = useState<CaseDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [labelVerdict, setLabelVerdict] = useState<Verdict>("safe");
  const [labelNote, setLabelNote] = useState("");
  const [isSubmittingLabel, setIsSubmittingLabel] = useState(false);
  const [labelError, setLabelError] = useState<string | null>(null);
  const toast = useToast();

  useEffect(() => {
    let cancelled = false;
    setCaseData(null);
    setError(null);

    getCase(caseId)
      .then((data) => {
        if (cancelled) return;
        setCaseData(data);
        setLabelVerdict(data.latest_label?.analyst_verdict ?? data.verdict);
        setLabelNote(data.latest_label?.note ?? "");
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load case.");
      });

    return () => {
      cancelled = true;
    };
  }, [caseId]);

  const handleDelete = async () => {
    if (!window.confirm("Delete this case? This also removes the stored raw email.")) return;
    setIsDeleting(true);
    try {
      await deleteCase(caseId);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete case.");
      setIsDeleting(false);
    }
  };

  const handleSubmitLabel = async () => {
    setIsSubmittingLabel(true);
    setLabelError(null);
    try {
      const label = await submitLabel(caseId, {
        analyst_verdict: labelVerdict,
        note: labelNote.trim() || undefined,
      });
      setCaseData((prev) => (prev ? { ...prev, latest_label: label } : prev));
      toast({ title: "Label submitted", description: `Case labeled ${label.analyst_verdict}.` });
    } catch (err) {
      setLabelError(err instanceof Error ? err.message : "Failed to submit label.");
    } finally {
      setIsSubmittingLabel(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <Button variant="link" icon={ArrowLeft} onClick={onBack} className="self-start">
        Back to cases
      </Button>

      {error && <ErrorState message={error} />}

      {!caseData && !error && (
        <Card>
          <LoadingState label="Loading case…" lines={4} />
        </Card>
      )}

      {caseData && (
        <>
          <Card>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="flex flex-col gap-2">
                <VerdictBadge verdict={caseData.verdict} score={caseData.score} />
                {caseData.latest_label && (
                  <p className="text-sm text-fg-secondary">
                    <span className="font-semibold text-fg">Human label:</span>{" "}
                    <span className="capitalize">{caseData.latest_label.analyst_verdict}</span>
                    {" by "}
                    {caseData.latest_label.labeled_by}
                    {" · "}
                    {new Date(caseData.latest_label.created_at).toLocaleString()}
                    {caseData.latest_label.note && (
                      <span className="block text-fg-secondary">“{caseData.latest_label.note}”</span>
                    )}
                  </p>
                )}
              </div>
              <Button
                variant="secondary"
                tone="danger"
                size="sm"
                icon={Trash2}
                onClick={handleDelete}
                loading={isDeleting}
                loadingText="Deleting…"
              >
                Delete case
              </Button>
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-fg-secondary sm:grid-cols-2">
              <div>
                <dt className="inline font-semibold text-fg">Sender: </dt>
                <dd className="inline">{caseData.from_addr ?? "—"}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Subject: </dt>
                <dd className="inline">{caseData.subject ?? "—"}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Filename: </dt>
                <dd className="inline">{caseData.filename}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Analyzed: </dt>
                <dd className="inline">{new Date(caseData.created_at).toLocaleString()}</dd>
              </div>
            </dl>
          </Card>

          <Card>
            <h2 className="text-base font-semibold text-fg">Analyst Feedback</h2>
            <p className="mt-1 text-sm text-fg-secondary">
              Agree with the machine verdict as-is, or change it below before submitting to
              correct it. Submitting again relabels the case — the prior label stays in history.
            </p>
            <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
              <Field label="Verdict">
                <Select
                  value={labelVerdict}
                  onChange={(event) => setLabelVerdict(event.target.value as Verdict)}
                  className="sm:w-40"
                >
                  <option value="safe">Safe</option>
                  <option value="suspicious">Suspicious</option>
                  <option value="malicious">Malicious</option>
                </Select>
              </Field>
              <Field label="Note (optional)" className="flex-1">
                <Input
                  type="text"
                  value={labelNote}
                  onChange={(event) => setLabelNote(event.target.value)}
                  placeholder="Why are you agreeing or correcting this verdict?"
                />
              </Field>
              <Button
                variant="primary"
                onClick={handleSubmitLabel}
                loading={isSubmittingLabel}
                loadingText="Submitting…"
              >
                Submit Label
              </Button>
            </div>
            {labelError && <ErrorState message={labelError} className="mt-3" />}
          </Card>

          <AiAuthoredFlag indicators={caseData.indicators} />

          <AIAnalystSummary narrative={caseData.analyst_narrative} model={caseData.analyst_model} />

          <ResponsePlaybookPanel caseId={caseData.id} />

          <InvestigationPanel entityId={caseData.id} />

          <section>
            <SectionHeading>Indicators</SectionHeading>
            <IndicatorList indicators={caseData.indicators} />
          </section>

          <section>
            <SectionHeading>Framework Mapping</SectionHeading>
            <FrameworkMappingPanel frameworkMappings={caseData.framework_mappings} />
          </section>
        </>
      )}
    </div>
  );
}
