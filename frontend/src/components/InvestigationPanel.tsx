import { useEffect, useState } from "react";
import {
  getCaseInvestigation,
  investigateCase,
} from "../api/client";
import type { Investigation } from "../types/analysis";

const SEVERITY_STYLES: Record<string, string> = {
  strong: "bg-emerald-100 text-emerald-800 border-emerald-300",
  moderate: "bg-amber-100 text-amber-800 border-amber-300",
  thin: "bg-slate-100 text-slate-600 border-slate-300",
};

const BAND_STYLES: Record<string, string> = {
  normal: "bg-slate-100 text-slate-600 border-slate-300",
  elevated: "bg-amber-100 text-amber-800 border-amber-300",
  attack_forming: "bg-red-100 text-red-800 border-red-300",
};

interface InvestigationPanelProps {
  entityId: string;
  // Defaults to the email-case endpoints so existing CaseDetail usage is unchanged.
  // IncidentDetail passes the incident-bound functions — same reuse pattern as
  // ResponsePlaybookPanel's fetchPlaybook/submitAction props.
  fetchInvestigation?: (entityId: string) => Promise<Investigation>;
  runInvestigation?: (entityId: string) => Promise<Investigation>;
}

export default function InvestigationPanel({
  entityId,
  fetchInvestigation = getCaseInvestigation,
  runInvestigation = investigateCase,
}: InvestigationPanelProps) {
  const [investigation, setInvestigation] = useState<Investigation | null>(null);
  const [status, setStatus] = useState<"loading" | "none" | "ready" | "error">("loading");
  const [error, setError] = useState<string | null>(null);
  const [isRunning, setIsRunning] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setStatus("loading");
    setInvestigation(null);
    setError(null);

    fetchInvestigation(entityId)
      .then((data) => {
        if (cancelled) return;
        setInvestigation(data);
        setStatus("ready");
      })
      .catch((err) => {
        if (cancelled) return;
        // A 404 ("no investigation yet") is an expected, not-yet-run state, not an error.
        if (err instanceof Error && /no investigation has been run/i.test(err.message)) {
          setStatus("none");
        } else {
          setError(err instanceof Error ? err.message : "Failed to load investigation.");
          setStatus("error");
        }
      });

    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entityId]);

  const handleRun = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const data = await runInvestigation(entityId);
      setInvestigation(data);
      setStatus("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to run investigation.");
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold text-slate-800">Investigation</h2>
          <p className="mt-1 text-sm text-slate-500">
            Correlates Cordon&apos;s own signals for the actor(s) involved — sender history,
            related cases and incidents, threat-intel hits, early-warning threat level, and
            behavioral findings — into one grounded report with a recommended response.
            Recommends only; nothing here executes automatically.
          </p>
        </div>
        <button
          onClick={handleRun}
          disabled={isRunning}
          className="whitespace-nowrap rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
        >
          {isRunning ? "Investigating…" : investigation ? "Re-investigate" : "Investigate"}
        </button>
      </div>

      {error && <p className="mt-3 text-sm text-red-700">{error}</p>}
      {status === "loading" && <p className="mt-3 text-sm text-slate-500">Loading…</p>}
      {status === "none" && !error && (
        <p className="mt-3 text-sm text-slate-500">
          No investigation has been run yet. Click Investigate to assemble one now.
        </p>
      )}

      {investigation && <InvestigationBody investigation={investigation} />}
    </section>
  );
}

function InvestigationBody({ investigation: inv }: { investigation: Investigation }) {
  return (
    <div className="mt-5 flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
        <span className="rounded-full border border-slate-300 bg-slate-50 px-2.5 py-0.5 font-medium uppercase tracking-wide">
          {inv.trigger === "auto" ? "Auto-triggered" : "On-demand"}
        </span>
        {inv.actor && <span>Actor: {inv.actor}</span>}
        <span>Updated {new Date(inv.updated_at).toLocaleString()}</span>
      </div>

      {/* Grounded narrative */}
      <div className="rounded-lg border border-indigo-200 bg-indigo-50 p-4">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-indigo-900">Investigation Summary</h3>
          {inv.summary_evidence_strength && (
            <span
              className={`rounded-full border px-2 py-0.5 text-xs font-medium uppercase tracking-wide ${SEVERITY_STYLES[inv.summary_evidence_strength]}`}
            >
              {inv.summary_evidence_strength} evidence
            </span>
          )}
        </div>
        {inv.summary ? (
          <p className="mt-2 text-sm leading-relaxed text-indigo-950">{inv.summary}</p>
        ) : (
          <p className="mt-2 text-sm text-indigo-800">
            No AI narrative available for this investigation — the deterministic findings
            below are unaffected. (Either the AI reasoning layer is disabled, or there wasn&apos;t
            enough gathered evidence to ground one.)
          </p>
        )}
      </div>

      {/* Scope / blast radius */}
      <div>
        <h3 className="text-sm font-semibold text-slate-700">Scope</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          <span
            className={`rounded-full border px-2.5 py-0.5 text-xs font-medium ${
              inv.scope.possible_account_compromise
                ? "border-red-300 bg-red-100 text-red-800"
                : "border-emerald-300 bg-emerald-100 text-emerald-800"
            }`}
          >
            {inv.scope.possible_account_compromise
              ? "Possible account compromise"
              : "No compromise signals found"}
          </span>
          {inv.scope.possible_additional_targets && (
            <span className="rounded-full border border-amber-300 bg-amber-100 px-2.5 py-0.5 text-xs font-medium text-amber-800">
              Other recipients likely targeted
            </span>
          )}
        </div>
        {inv.scope.compromise_signals.length > 0 && (
          <ul className="mt-2 list-disc pl-5 text-sm text-slate-600">
            {inv.scope.compromise_signals.map((signal) => (
              <li key={signal}>{signal}</li>
            ))}
          </ul>
        )}
        {inv.scope.other_recipients_same_sender.length > 0 && (
          <p className="mt-2 text-sm text-slate-600">
            Also sent to: {inv.scope.other_recipients_same_sender.join(", ")}
          </p>
        )}
      </div>

      {/* Sender intelligence */}
      {inv.sender_intelligence && (
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Sender Intelligence</h3>
          <p className="mt-2 text-sm text-slate-600">
            <span className="font-medium text-slate-800">{inv.sender_intelligence.domain}</span>{" "}
            is classified{" "}
            <span className="font-medium capitalize">
              {inv.sender_intelligence.classification.replace("_", " ")}
            </span>{" "}
            ({inv.sender_intelligence.seen_count} prior email
            {inv.sender_intelligence.seen_count === 1 ? "" : "s"} to this account
            {inv.sender_intelligence.is_trusted_vendor ? ", trusted vendor" : ""}).
          </p>
        </div>
      )}

      {/* Threat level */}
      {inv.threat_level && (
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Early-Warning Threat Level</h3>
          <div className="mt-2 flex items-center gap-2">
            <span
              className={`rounded-full border px-2.5 py-0.5 text-xs font-medium uppercase tracking-wide ${BAND_STYLES[inv.threat_level.band] ?? BAND_STYLES.normal}`}
            >
              {inv.threat_level.band.replace("_", " ")}
            </span>
            <span className="text-sm text-slate-600">
              {inv.threat_level.score.toFixed(0)}/100, trend {inv.threat_level.trend}
            </span>
          </div>
        </div>
      )}

      {/* Threat intel hits */}
      {inv.threat_intel_hits.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Threat-Intel Matches</h3>
          <ul className="mt-2 flex flex-col gap-1 text-sm text-slate-600">
            {inv.threat_intel_hits.map((hit, i) => (
              <li key={`${hit.id}-${i}`}>
                <span className="font-medium text-slate-800">{hit.id}</span>
                {hit.title ? ` — ${hit.title}` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* UEBA findings */}
      {inv.ueba_findings.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Behavioral Findings</h3>
          <ul className="mt-2 flex flex-col gap-2">
            {inv.ueba_findings.map((finding, i) => (
              <li
                key={`${finding.id}-${i}`}
                className="rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm"
              >
                <span className="font-medium text-slate-800">{finding.title}</span>
                <span className="text-slate-500"> — {finding.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Related cases / incidents */}
      {(inv.related_cases.length > 0 || inv.related_incidents.length > 0) && (
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Correlated Cases &amp; Incidents</h3>
          <ul className="mt-2 flex flex-col gap-1 text-sm text-slate-600">
            {inv.related_cases.map((rc) => (
              <li key={rc.id}>
                {new Date(rc.created_at).toLocaleDateString()} — {rc.subject ?? "(no subject)"}{" "}
                <span className="capitalize text-slate-500">({rc.verdict})</span>
              </li>
            ))}
            {inv.related_incidents.map((ri) => (
              <li key={ri.id}>
                {new Date(ri.created_at).toLocaleDateString()} — {ri.title}{" "}
                <span className="capitalize text-slate-500">({ri.verdict})</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Timeline */}
      {inv.timeline.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Timeline</h3>
          <ol className="mt-2 flex flex-col gap-2 border-l-2 border-slate-200 pl-4">
            {inv.timeline.map((entry, i) => (
              <li key={`${entry.source_id}-${i}`} className="text-sm">
                <span className="text-xs text-slate-400">
                  {new Date(entry.timestamp).toLocaleString()}
                </span>
                <p className="text-slate-700">{entry.description}</p>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Recommended response */}
      {inv.recommended_steps.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-700">Recommended Response</h3>
          <p className="mt-1 text-xs text-slate-500">
            Mapped from the same deterministic playbook as the Response Playbook above —
            approve and track each step there.
          </p>
          <ul className="mt-2 flex flex-col gap-2">
            {inv.recommended_steps.map((step) => (
              <li key={step.step_id} className="rounded-lg border border-slate-200 p-3">
                <p className="text-sm font-semibold text-slate-800">{step.title}</p>
                <p className="mt-0.5 text-sm text-slate-600">{step.description}</p>
                {step.control_refs.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {step.control_refs.map((ref) => (
                      <span
                        key={`${ref.framework_key}-${ref.control_id}`}
                        title={ref.control_name}
                        className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-xs text-slate-600"
                      >
                        {ref.framework_key}: {ref.control_id}
                      </span>
                    ))}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
