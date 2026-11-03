import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
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
import FrameworkMappingPanel from "../FrameworkMappingPanel";
import InvestigationPanel from "../InvestigationPanel";
import ResponsePlaybookPanel from "../ResponsePlaybookPanel";
import VerdictBadge from "../VerdictBadge";
import EvidenceEventsTable from "./EvidenceEventsTable";
import FindingList from "./FindingList";
import {
  Button,
  Card,
  ErrorState,
  Field,
  Input,
  LoadingState,
  SectionHeading,
  Select,
} from "../ui";

interface IncidentDetailProps {
  incidentId: string;
  onBack: () => void;
  onDeleted: () => void;
}

export default function IncidentDetail({ incidentId, onBack, onDeleted }: IncidentDetailProps) {
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

  const handleDelete = async () => {
    if (!window.confirm("Delete this incident?")) return;
    setIsDeleting(true);
    try {
      await deleteIncident(incidentId);
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

      {!incident && !error && <LoadingState label="Loading incident…" />}

      {incident && (
        <>
          <Card>
            <div className="flex flex-wrap items-start justify-between gap-4">
              <div className="flex flex-col gap-2">
                <VerdictBadge verdict={incident.verdict} score={incident.score} />
                {incident.latest_label && (
                  <p className="text-sm text-fg-secondary">
                    <span className="font-semibold text-fg">Human label:</span>{" "}
                    <span className="capitalize">{incident.latest_label.analyst_verdict}</span>
                    {" by "}
                    {incident.latest_label.labeled_by}
                    {" · "}
                    {new Date(incident.latest_label.created_at).toLocaleString()}
                    {incident.latest_label.note && (
                      <span className="block text-fg-secondary">“{incident.latest_label.note}”</span>
                    )}
                  </p>
                )}
              </div>
              <Button
                tone="danger"
                size="sm"
                onClick={handleDelete}
                loading={isDeleting}
                loadingText="Deleting…"
              >
                Delete incident
              </Button>
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-fg-secondary sm:grid-cols-2">
              <div>
                <dt className="inline font-semibold text-fg">Actor: </dt>
                <dd className="inline">{incident.actor}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Title: </dt>
                <dd className="inline">{incident.title}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Detection window: </dt>
                <dd className="inline">
                  {new Date(incident.window_start).toLocaleString()} –{" "}
                  {new Date(incident.window_end).toLocaleString()}
                </dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Detected: </dt>
                <dd className="inline">{new Date(incident.created_at).toLocaleString()}</dd>
              </div>
            </dl>
          </Card>

          <Card>
            <h2 className="text-base font-semibold text-fg">Analyst Feedback</h2>
            <p className="mt-1 text-sm text-fg-secondary">
              Agree with the machine verdict as-is, or change it below before submitting to
              correct it. Submitting again relabels the incident — the prior label stays in
              history.
            </p>
            <div className="mt-4 flex flex-col gap-3 sm:flex-row sm:items-end">
              <Field label="Verdict">
                <Select
                  value={labelVerdict}
                  onChange={(event) => setLabelVerdict(event.target.value as Verdict)}
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
            {labelError && <ErrorState message={labelError} className="mt-2" />}
          </Card>

          <ResponsePlaybookPanel
            caseId={incident.id}
            fetchPlaybook={getIncidentRemediationPlaybook}
            submitAction={submitIncidentRemediationAction}
          />

          <InvestigationPanel
            entityId={incident.id}
            fetchInvestigation={getIncidentInvestigation}
            runInvestigation={investigateIncident}
          />

          <section>
            <SectionHeading>Findings</SectionHeading>
            <FindingList findings={incident.findings} />
          </section>

          <section>
            <SectionHeading>Evidence Events</SectionHeading>
            <EvidenceEventsTable events={incident.evidence_events} />
          </section>

          <section>
            <SectionHeading>Framework Mapping</SectionHeading>
            <FrameworkMappingPanel frameworkMappings={incident.framework_mappings} />
          </section>
        </>
      )}
    </div>
  );
}
