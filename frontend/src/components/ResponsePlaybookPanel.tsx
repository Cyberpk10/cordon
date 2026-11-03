import { useEffect, useState } from "react";
import { getRemediationPlaybook, submitRemediationAction } from "../api/client";
import type { PlaybookStep, RemediationPlaybook } from "../types/analysis";

const STATUS_STYLES: Record<string, string> = {
  recommended: "bg-surface-raised text-fg-secondary border-line-strong",
  approved: "bg-warning/10 text-warning border-warning/35",
  done: "bg-success/10 text-success border-success/35",
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
}

export default function ResponsePlaybookPanel({
  caseId,
  fetchPlaybook = getRemediationPlaybook,
  submitAction = submitRemediationAction,
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
    <section className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
      <h2 className="text-lg font-semibold text-fg">Response Playbook</h2>
      <p className="mt-1 text-sm text-fg-secondary">
        Recommended next steps derived from this case&apos;s indicators. Cordon never performs
        these automatically — an operator approves and marks each one done.
      </p>

      {error && <p className="mt-3 text-sm text-danger">{error}</p>}

      {!playbook && !error && <p className="mt-3 text-sm text-fg-secondary">Loading playbook…</p>}

      {playbook && playbook.steps.length === 0 && (
        <p className="mt-3 text-sm text-fg-secondary">
          No remediation steps recommended for this case.
        </p>
      )}

      {playbook && playbook.steps.length > 0 && (
        <ul className="mt-4 flex flex-col gap-3">
          {playbook.steps.map((step) => (
            <li key={step.step_id} className="rounded-lg border border-line p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-fg">{step.title}</h3>
                  <p className="mt-1 text-sm text-fg-secondary">{step.description}</p>
                </div>
                <span
                  className={`whitespace-nowrap rounded-full border px-2.5 py-0.5 text-xs font-semibold uppercase tracking-wide ${STATUS_STYLES[step.status]}`}
                >
                  {step.status}
                </span>
              </div>

              {step.control_refs.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {step.control_refs.map((ref) => (
                    <span
                      key={`${ref.framework_key}-${ref.control_id}`}
                      title={ref.control_name}
                      className="rounded border border-line bg-surface-panel px-1.5 py-0.5 text-xs text-fg-secondary"
                    >
                      {ref.framework_key}: {ref.control_id}
                    </span>
                  ))}
                </div>
              )}

              {step.actor && (
                <p className="mt-2 text-xs text-fg-secondary">
                  {step.status === "done" ? "Marked done" : "Approved"} by {step.actor}
                  {step.acted_at && ` · ${new Date(step.acted_at).toLocaleString()}`}
                  {step.note && <span className="block">“{step.note}”</span>}
                </p>
              )}

              <div className="mt-3 flex gap-2">
                {step.status === "recommended" && (
                  <button
                    onClick={() => handleAction(step, "approved")}
                    disabled={actingStepId === step.step_id}
                    className="rounded-lg bg-accent-fill px-3 py-1.5 text-xs font-semibold text-fg-on-fill shadow-sm transition hover:bg-accent-fill-hover disabled:cursor-not-allowed disabled:bg-line-strong"
                  >
                    {actingStepId === step.step_id ? "Approving…" : "Approve"}
                  </button>
                )}
                {step.status === "approved" && (
                  <button
                    onClick={() => handleAction(step, "done")}
                    disabled={actingStepId === step.step_id}
                    className="rounded-lg border border-success/35 px-3 py-1.5 text-xs font-semibold text-success hover:bg-success/10 disabled:cursor-not-allowed disabled:opacity-50"
                  >
                    {actingStepId === step.step_id ? "Marking…" : "Mark done"}
                  </button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
