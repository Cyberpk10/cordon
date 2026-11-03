import { useEffect, useState } from "react";
import { deleteCase, getCase, submitLabel } from "../api/client";
import type { CaseDetail as CaseDetailType, Verdict } from "../types/analysis";
import AiAuthoredFlag from "./AiAuthoredFlag";
import AIAnalystSummary from "./AIAnalystSummary";
import IndicatorList from "./IndicatorList";
import InvestigationPanel from "./InvestigationPanel";
import ResponsePlaybookPanel from "./ResponsePlaybookPanel";
import ChannelBadge from "./ChannelBadge";
import AnalysisResultCard, { AnalysisResultSkeleton, summarizeIndicators } from "./analyze/AnalysisResultCard";
import { AnalystFeedbackCard, HumanLabelNote } from "./AnalystLabel";
import PageActions from "./shell/PageActions";
import { ArrowLeft, Trash2 } from "lucide-react";
import { Button, ErrorState, SectionHeading, useConfirm, useToast } from "./ui";

const CASE_ANCHOR = "case-indicator-";

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
  const confirm = useConfirm();

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
    const ok = await confirm({
      title: "Delete this case?",
      description: "This permanently removes the case and its stored raw email. This can't be undone.",
      confirmLabel: "Delete case",
      tone: "danger",
    });
    if (!ok) return;
    setIsDeleting(true);
    try {
      await deleteCase(caseId);
      toast({ title: "Case deleted" });
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

      {!caseData && !error && <AnalysisResultSkeleton />}

      {caseData && (
        <>
          <PageActions>
            <Button
              tone="danger"
              size="sm"
              icon={Trash2}
              onClick={handleDelete}
              loading={isDeleting}
              loadingText="Deleting…"
            >
              Delete case
            </Button>
          </PageActions>

          <AnalysisResultCard
            verdict={caseData.verdict}
            score={caseData.score}
            summary={summarizeIndicators(caseData.verdict, caseData.indicators, {
              none: "No phishing indicators were detected in this message.",
              signal: "indicator",
            })}
            footnote={
              caseData.latest_label && (
                <HumanLabelNote label={caseData.latest_label} machineVerdict={caseData.verdict} />
              )
            }
            details={[
              { label: "Subject", value: caseData.subject ?? "—", wide: true },
              { label: "Sender", value: caseData.from_addr ?? "—" },
              { label: "Channel", value: <ChannelBadge channel={caseData.channel} /> },
              { label: "Filename", value: <span className="font-mono text-xs">{caseData.filename}</span> },
              { label: "Analyzed", value: new Date(caseData.created_at).toLocaleString() },
            ]}
            indicators={caseData.indicators}
            indicatorAnchorPrefix={CASE_ANCHOR}
            frameworkMappings={caseData.framework_mappings}
          />

          <AiAuthoredFlag indicators={caseData.indicators} />

          <AIAnalystSummary narrative={caseData.analyst_narrative} model={caseData.analyst_model} />

          <AnalystFeedbackCard
            noun="case"
            verdict={labelVerdict}
            note={labelNote}
            onVerdictChange={setLabelVerdict}
            onNoteChange={setLabelNote}
            onSubmit={handleSubmitLabel}
            isSubmitting={isSubmittingLabel}
            error={labelError}
          />

          <ResponsePlaybookPanel caseId={caseData.id} />

          <InvestigationPanel entityId={caseData.id} />

          {caseData.indicators.length > 0 && (
            <section>
              <SectionHeading>All indicators ({caseData.indicators.length})</SectionHeading>
              <IndicatorList indicators={caseData.indicators} idPrefix={CASE_ANCHOR} />
            </section>
          )}
        </>
      )}
    </div>
  );
}
