import { useEffect, useState } from "react";
import { ArrowLeft, Trash2 } from "lucide-react";
import {
  deleteIncident,
  getIncident,
  getIncidentInvestigation,
  getIncidentRemediationPlaybook,
  investigateIncident,
  submitIncidentLabel,
  submitIncidentRemediationAction,
} from "../../api/client";
import type { IncidentDetail as IncidentDetailType, Verdict } from "../../types/analysis";
import InvestigationPanel from "../InvestigationPanel";
import ResponsePlaybookPanel from "../ResponsePlaybookPanel";
import AnalysisResultCard, { AnalysisResultSkeleton, summarizeIndicators } from "../analyze/AnalysisResultCard";
import { AnalystFeedbackCard, HumanLabelNote } from "../AnalystLabel";
import PageActions from "../shell/PageActions";
import EvidenceEventsTable from "./EvidenceEventsTable";
import FindingList from "./FindingList";
import { Badge, Button, ErrorState, SectionHeading, useConfirm, useToast } from "../ui";

const FINDING_ANCHOR = "incident-finding-";

interface IncidentDetailProps {
  incidentId: string;
  onBack: () => void;
  onDeleted: () => void;
}

export default function IncidentDetail({ incidentId, onBack, onDeleted }: IncidentDetailProps) {
  const confirm = useConfirm();
  const toast = useToast();
  const [incident, setIncident] = useState<IncidentDetailType | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [labelVerdict, setLabelVerdict] = useState<Verdict>("safe");
  const [labelNote, setLabelNote] = useState("");
  const [isSubmittingLabel, setIsSubmittingLabel] = useState(false);
  const [labelError, setLabelError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setIncident(null);
    setError(null);

    getIncident(incidentId)
      .then((data) => {
        if (cancelled) return;
        setIncident(data);
        setLabelVerdict(data.latest_label?.analyst_verdict ?? data.verdict);
        setLabelNote(data.latest_label?.note ?? "");
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load incident.");
      });

    return () => {
      cancelled = true;
    };
  }, [incidentId]);

  const signals = (incident?.findings ?? []).map((f) => ({ ...f, score: f.points }));

  const handleDelete = async () => {
    const ok = await confirm({
      title: "Delete this incident?",
      description: "This permanently removes the incident. This can't be undone.",
      confirmLabel: "Delete incident",
      tone: "danger",
    });
    if (!ok) return;
    setIsDeleting(true);
    try {
      await deleteIncident(incidentId);
      toast({ title: "Incident deleted" });
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to delete incident.");
      setIsDeleting(false);
    }
  };

  const handleSubmitLabel = async () => {
    setIsSubmittingLabel(true);
    setLabelError(null);
    try {
      const label = await submitIncidentLabel(incidentId, {
        analyst_verdict: labelVerdict,
        note: labelNote.trim() || undefined,
      });
      setIncident((prev) => (prev ? { ...prev, latest_label: label } : prev));
      toast({ title: "Label submitted", description: `Incident labeled ${label.analyst_verdict}.` });
    } catch (err) {
      setLabelError(err instanceof Error ? err.message : "Failed to submit label.");
    } finally {
      setIsSubmittingLabel(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <Button variant="link" icon={ArrowLeft} className="self-start" onClick={onBack}>
        Back to detections
      </Button>

      {error && <ErrorState message={error} />}

      {!incident && !error && <AnalysisResultSkeleton />}

      {incident && (
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
              Delete incident
            </Button>
          </PageActions>

          <AnalysisResultCard
            verdict={incident.verdict}
            score={incident.score}
            summary={summarizeIndicators(incident.verdict, signals, {
              none: "No detections fired for this incident.",
              signal: "finding",
            })}
            footnote={
              incident.latest_label && (
                <HumanLabelNote label={incident.latest_label} machineVerdict={incident.verdict} />
              )
            }
            details={[
              { label: "Incident", value: incident.title, wide: true },
              { label: "Actor", value: incident.actor },
              {
                label: "Detection window",
                value: `${new Date(incident.window_start).toLocaleString()} – ${new Date(incident.window_end).toLocaleString()}`,
              },
              {
                label: "Detections",
                value: (
                  <span className="flex flex-wrap gap-1">
                    {incident.detection_types.map((type) => (
                      <Badge key={type} size="sm">
                        {type}
                      </Badge>
                    ))}
                  </span>
                ),
              },
              { label: "Created", value: new Date(incident.created_at).toLocaleString() },
            ]}
            indicators={signals}
            indicatorAnchorPrefix={FINDING_ANCHOR}
            indicatorsLabel="Top findings"
            frameworkMappings={incident.framework_mappings}
          />

          <AnalystFeedbackCard
            noun="incident"
            verdict={labelVerdict}
            note={labelNote}
            onVerdictChange={setLabelVerdict}
            onNoteChange={setLabelNote}
            onSubmit={handleSubmitLabel}
            isSubmitting={isSubmittingLabel}
            error={labelError}
          />

          <ResponsePlaybookPanel
            caseId={incident.id}
            fetchPlaybook={getIncidentRemediationPlaybook}
            submitAction={submitIncidentRemediationAction}
            noun="incident"
          />

          <InvestigationPanel
            entityId={incident.id}
            fetchInvestigation={getIncidentInvestigation}
            runInvestigation={investigateIncident}
          />

          <section>
            <SectionHeading>All findings ({incident.findings.length})</SectionHeading>
            <FindingList findings={incident.findings} idPrefix={FINDING_ANCHOR} />
          </section>

          <section>
            <SectionHeading>Evidence Events</SectionHeading>
            <EvidenceEventsTable events={incident.evidence_events} />
          </section>
        </>
      )}
    </div>
  );
}
