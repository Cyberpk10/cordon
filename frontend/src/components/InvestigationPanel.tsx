import { useEffect, useState } from "react";
import {
  getCaseInvestigation,
  investigateCase,
} from "../api/client";
import type { Investigation } from "../types/analysis";
import { FileSearch, Sparkles } from "lucide-react";
import ControlRefChips from "./ControlRefChips";
import { Badge, Button, Card, EmptyState, ErrorState, LoadingState, type BadgeTone } from "./ui";

const EVIDENCE_TONE: Record<string, BadgeTone> = {
  strong: "success",
  moderate: "warning",
  thin: "neutral",
};

const BAND_TONE: Record<string, BadgeTone> = {
  normal: "neutral",
  elevated: "warning",
  attack_forming: "danger",
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
    <Card>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <h2 className="text-base font-semibold text-fg">Investigation</h2>
          <p className="mt-1 text-sm text-fg-secondary">
            Correlates Cordon&apos;s own signals for the actor(s) involved — sender history,
            related cases and incidents, threat-intel hits, early-warning threat level, and
            behavioral findings — into one grounded report with a recommended response.
            Recommends only; nothing here executes automatically.
          </p>
        </div>
        <Button
          variant="primary"
          icon={FileSearch}
          onClick={handleRun}
          loading={isRunning}
          loadingText="Investigating…"
        >
          {investigation ? "Re-investigate" : "Investigate"}
        </Button>
      </div>

      {error && <ErrorState message={error} className="mt-3" />}
      {status === "loading" && <LoadingState label="Loading investigation…" className="mt-3" />}
      {status === "none" && !error && (
        <EmptyState
          icon={FileSearch}
          title="No investigation has been run yet."
          description="Click Investigate to assemble one now."
          className="mt-3 rounded-control border border-dashed border-line"
        />
      )}

      {investigation && <InvestigationBody investigation={investigation} />}
    </Card>
  );
}

function InvestigationBody({ investigation: inv }: { investigation: Investigation }) {
  return (
    <div className="mt-5 flex flex-col gap-5">
      <div className="flex flex-wrap items-center gap-3 text-xs text-fg-secondary">
        <Badge caps>{inv.trigger === "auto" ? "Auto-triggered" : "On-demand"}</Badge>
        {inv.actor && <span>Actor: {inv.actor}</span>}
        <span>Updated {new Date(inv.updated_at).toLocaleString()}</span>
      </div>

      {/* Grounded narrative */}
      <div className="rounded-control border border-accent/25 bg-accent/10 p-4">
        <div className="flex items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
            <Sparkles aria-hidden="true" className="h-4 w-4 text-accent" />
            Investigation Summary
          </h3>
          {inv.summary_evidence_strength && (
            <Badge tone={EVIDENCE_TONE[inv.summary_evidence_strength] ?? "neutral"} caps>
              {inv.summary_evidence_strength} evidence
            </Badge>
          )}
        </div>
        {inv.summary ? (
          <p className="mt-2 text-sm leading-relaxed text-fg-secondary">{inv.summary}</p>
        ) : (
          <p className="mt-2 text-sm text-fg-secondary">
            No AI narrative available for this investigation — the deterministic findings
            below are unaffected. (Either the AI reasoning layer is disabled, or there wasn&apos;t
            enough gathered evidence to ground one.)
          </p>
        )}
      </div>

      {/* Scope / blast radius */}
      <div>
        <h3 className="text-sm font-semibold text-fg">Scope</h3>
        <div className="mt-2 flex flex-wrap gap-2">
          <Badge tone={inv.scope.possible_account_compromise ? "danger" : "success"}>
            {inv.scope.possible_account_compromise
              ? "Possible account compromise"
              : "No compromise signals found"}
          </Badge>
          {inv.scope.possible_additional_targets && (
            <Badge tone="warning">Other recipients likely targeted</Badge>
          )}
        </div>
        {inv.scope.compromise_signals.length > 0 && (
          <ul className="mt-2 list-disc pl-5 text-sm text-fg-secondary">
            {inv.scope.compromise_signals.map((signal) => (
              <li key={signal}>{signal}</li>
            ))}
          </ul>
        )}
        {inv.scope.other_recipients_same_sender.length > 0 && (
          <p className="mt-2 text-sm text-fg-secondary">
            Also sent to: {inv.scope.other_recipients_same_sender.join(", ")}
          </p>
        )}
      </div>

      {/* Sender intelligence */}
      {inv.sender_intelligence && (
        <div>
          <h3 className="text-sm font-semibold text-fg">Sender Intelligence</h3>
          <p className="mt-2 text-sm text-fg-secondary">
            <span className="font-semibold text-fg">{inv.sender_intelligence.domain}</span>{" "}
            is classified{" "}
            <span className="font-semibold capitalize">
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
          <h3 className="text-sm font-semibold text-fg">Early-Warning Threat Level</h3>
          <div className="mt-2 flex items-center gap-2">
            <Badge tone={BAND_TONE[inv.threat_level.band] ?? "neutral"} caps>
              {inv.threat_level.band.replace("_", " ")}
            </Badge>
            <span className="text-sm text-fg-secondary">
              {inv.threat_level.score.toFixed(0)}/100, trend {inv.threat_level.trend}
            </span>
          </div>
        </div>
      )}

      {/* Threat intel hits */}
      {inv.threat_intel_hits.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-fg">Threat-Intel Matches</h3>
          <ul className="mt-2 flex flex-col gap-1 text-sm text-fg-secondary">
            {inv.threat_intel_hits.map((hit, i) => (
              <li key={`${hit.id}-${i}`}>
                <span className="font-semibold text-fg">{hit.id}</span>
                {hit.title ? ` — ${hit.title}` : ""}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* UEBA findings */}
      {inv.ueba_findings.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-fg">Behavioral Findings</h3>
          <ul className="mt-2 flex flex-col gap-2">
            {inv.ueba_findings.map((finding, i) => (
              <li
                key={`${finding.id}-${i}`}
                className="rounded-control border border-line bg-surface-panel p-3 text-sm"
              >
                <span className="font-semibold text-fg">{finding.title}</span>
                <span className="text-fg-secondary"> — {finding.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Related cases / incidents */}
      {(inv.related_cases.length > 0 || inv.related_incidents.length > 0) && (
        <div>
          <h3 className="text-sm font-semibold text-fg">Correlated Cases &amp; Incidents</h3>
          <ul className="mt-2 flex flex-col gap-1 text-sm text-fg-secondary">
            {inv.related_cases.map((rc) => (
              <li key={rc.id}>
                {new Date(rc.created_at).toLocaleDateString()} — {rc.subject ?? "(no subject)"}{" "}
                <span className="capitalize text-fg-secondary">({rc.verdict})</span>
              </li>
            ))}
            {inv.related_incidents.map((ri) => (
              <li key={ri.id}>
                {new Date(ri.created_at).toLocaleDateString()} — {ri.title}{" "}
                <span className="capitalize text-fg-secondary">({ri.verdict})</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Timeline */}
      {inv.timeline.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-fg">Timeline</h3>
          <ol className="mt-2 flex flex-col gap-2 border-l-2 border-line pl-4">
            {inv.timeline.map((entry, i) => (
              <li key={`${entry.source_id}-${i}`} className="text-sm">
                <span className="text-xs text-fg-muted">
                  {new Date(entry.timestamp).toLocaleString()}
                </span>
                <p className="text-fg">{entry.description}</p>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Recommended response */}
      {inv.recommended_steps.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-fg">Recommended Response</h3>
          <p className="mt-1 text-xs text-fg-secondary">
            Mapped from the same deterministic playbook as the Response Playbook above —
            approve and track each step there.
          </p>
          <ul className="mt-2 flex flex-col gap-2">
            {inv.recommended_steps.map((step) => (
              <li key={step.step_id} className="rounded-control border border-line bg-surface-panel p-3">
                <p className="text-sm font-semibold text-fg">{step.title}</p>
                <p className="mt-0.5 text-sm text-fg-secondary">{step.description}</p>
                <ControlRefChips refs={step.control_refs} />
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
