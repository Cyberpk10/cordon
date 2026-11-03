import { useEffect, useState } from "react";
import { getRemediationPlaybook, submitRemediationAction } from "../api/client";
import type { PlaybookStep, RemediationPlaybook } from "../types/analysis";
import { Check, CheckCheck, ListChecks } from "lucide-react";
import ControlRefChips from "./ControlRefChips";
import { Badge, Button, Card, EmptyState, ErrorState, LoadingState, type BadgeTone } from "./ui";

const STATUS_TONE: Record<string, BadgeTone> = {
  recommended: "neutral",
  approved: "warning",
  done: "success",
};

interface ResponsePlaybookPanelProps {
  caseId: string;
  // Defaults to the email-case endpoints (/api/cases/...) so existing CaseDetail usage
  // is unchanged. IncidentDetail passes the incident-bound functions
  // (getIncidentRemediationPlaybook/submitIncidentRemediationAction) so this same panel
  // is reused for incidents (M5 Stage 1) rather than duplicated.
  fetchPlaybook?: (entityId: string) => Promise<RemediationPlaybook>;
  submitAction?: (
    entityId: string,
    stepId: string,
    params: { status: "approved" | "done"; note?: string }
  ) => Promise<void>;
  /** "case" (default) or "incident", for the panel's copy. */
  noun?: "case" | "incident";
}

export default function ResponsePlaybookPanel({
  caseId,
  fetchPlaybook = getRemediationPlaybook,
  submitAction = submitRemediationAction,
  noun = "case",
}: ResponsePlaybookPanelProps) {
  const [playbook, setPlaybook] = useState<RemediationPlaybook | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [actingStepId, setActingStepId] = useState<string | null>(null);

  const load = () => {
    fetchPlaybook(caseId)
      .then((data) => setPlaybook(data))
      .catch((err) => setError(err instanceof Error ? err.message : "Failed to load playbook."));
  };

  useEffect(() => {
    setPlaybook(null);
    setError(null);
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [caseId]);

  const handleAction = async (step: PlaybookStep, status: "approved" | "done") => {
    setActingStepId(step.step_id);
    setError(null);
    try {
      await submitAction(caseId, step.step_id, { status });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to record action.");
    } finally {
      setActingStepId(null);
    }
  };

  return (
    <Card>
      <h2 className="text-base font-semibold text-fg">Response Playbook</h2>
      <p className="mt-1 text-sm text-fg-secondary">
        Recommended next steps derived from this {noun}&apos;s {noun === "case" ? "indicators" : "findings"}. Cordon never performs
        these automatically — an operator approves and marks each one done.
      </p>

      {error && <ErrorState message={error} className="mt-3" />}

      {!playbook && !error && <LoadingState label="Loading playbook…" className="mt-3" />}

      {playbook && playbook.steps.length === 0 && (
        <EmptyState
          variant="inline"
          icon={ListChecks}
          title={`No remediation steps recommended for this ${noun}.`}
          className="justify-start"
        />
      )}

      {playbook && playbook.steps.length > 0 && (
        <ul className="mt-4 flex flex-col gap-3">
          {playbook.steps.map((step) => (
            <li key={step.step_id} className="rounded-control border border-line bg-surface-panel p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-fg">{step.title}</h3>
                  <p className="mt-1 text-sm text-fg-secondary">{step.description}</p>
                </div>
                <Badge tone={STATUS_TONE[step.status] ?? "neutral"} caps>
                  {step.status}
                </Badge>
              </div>

              <ControlRefChips refs={step.control_refs} />

              {step.actor && (
                <p className="mt-2 text-xs text-fg-secondary">
                  {step.status === "done" ? "Marked done" : "Approved"} by {step.actor}
                  {step.acted_at && ` · ${new Date(step.acted_at).toLocaleString()}`}
                  {step.note && <span className="block">“{step.note}”</span>}
                </p>
              )}

              <div className="mt-3 flex gap-2">
                {step.status === "recommended" && (
                  <Button
                    variant="primary"
                    size="sm"
                    icon={Check}
                    onClick={() => handleAction(step, "approved")}
                    loading={actingStepId === step.step_id}
                    loadingText="Approving…"
                  >
                    Approve
                  </Button>
                )}
                {step.status === "approved" && (
                  <Button
                    variant="secondary"
                    tone="success"
                    size="sm"
                    icon={CheckCheck}
                    onClick={() => handleAction(step, "done")}
                    loading={actingStepId === step.step_id}
                    loadingText="Marking…"
                  >
                    Mark done
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
