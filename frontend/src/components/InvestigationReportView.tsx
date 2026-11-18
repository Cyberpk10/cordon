import { useState } from "react";
import { AlertTriangle, Bot, ListChecks, Radar, ShieldCheck, Users } from "lucide-react";
import type { Investigation, InvestigationEvidenceItem, InvestigationReport } from "../types/analysis";
import { Badge, type BadgeTone } from "./ui";

const CONFIDENCE_TONE: Record<InvestigationReport["confidence"]["level"], BadgeTone> = {
  high: "success",
  medium: "warning",
  low: "neutral",
};

const CAMPAIGN: Record<InvestigationReport["campaign"]["status"], { label: string; tone: BadgeTone }> = {
  one_off: { label: "One-off", tone: "neutral" },
  possible_campaign: { label: "Possible campaign", tone: "warning" },
  wave: { label: "Part of a wave", tone: "danger" },
};

function EvidenceChips({
  ids,
  open,
  onToggle,
}: {
  ids: string[];
  open: string | null;
  onToggle: (id: string) => void;
}) {
  return (
    <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
      {ids.map((id) => (
        <button
          key={id}
          type="button"
          onClick={() => onToggle(id)}
          aria-expanded={open === id}
          className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold transition-colors ${
            open === id ? "bg-accent text-white" : "bg-accent/15 text-accent hover:bg-accent/25"
          }`}
        >
          {id}
        </button>
      ))}
    </span>
  );
}

function EvidenceText({ item }: { item: InvestigationEvidenceItem | undefined }) {
  if (!item) return null;
  // Rendered as text: email-derived parts arrive wrapped in <untrusted> markers, shown literally.
  return (
    <p className="mt-1 rounded-control border border-line bg-surface-panel px-3 py-2 text-xs text-fg-secondary">
      <span className="font-mono font-semibold text-fg">{item.id}</span> · {item.source.replace(/_/g, " ")} ·{" "}
      {item.text}
    </p>
  );
}

/** The agent's (or rules engine's) structured investigation: grounded claims with their
 * evidence, confidence, hypothesis, campaign, blast radius and the recommended response. */
export default function InvestigationReportView({ investigation }: { investigation: Investigation }) {
  const report = investigation.report!;
  const evidence = new Map((investigation.evidence ?? []).map((e) => [e.id, e]));
  const [openEv, setOpenEv] = useState<string | null>(null);
  const toggle = (id: string) => setOpenEv((cur) => (cur === id ? null : id));
  const campaign = CAMPAIGN[report.campaign.status];
  const rec = report.recommendation;

  return (
    <div className="flex flex-col gap-5">
      {/* Narrative + evidence chain */}
      <div className="rounded-control border border-accent/25 bg-accent/10 p-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
            <Bot aria-hidden="true" className="h-4 w-4 text-accent" />
            Analyst narrative
          </h3>
          <div className="flex flex-wrap gap-2">
            <Badge tone={report.engine === "agent" ? "accent" : "neutral"} caps>
              {report.engine === "agent" ? "AI-written, verified" : "Rules-based"}
            </Badge>
            <Badge tone={CONFIDENCE_TONE[report.confidence.level]} caps>
              {report.confidence.level} confidence
            </Badge>
          </div>
        </div>
        <ul className="mt-3 flex flex-col gap-2">
          {report.claims.map((claim, i) => (
            <li key={i} className="text-sm leading-relaxed text-fg-secondary">
              {claim.text}
              <EvidenceChips ids={claim.evidence_ids} open={openEv} onToggle={toggle} />
              {openEv && claim.evidence_ids.includes(openEv) && <EvidenceText item={evidence.get(openEv)} />}
            </li>
          ))}
        </ul>
        {report.unsupported_claims_removed > 0 && (
          <p className="mt-3 text-xs text-fg-muted">
            {report.unsupported_claims_removed} statement{report.unsupported_claims_removed === 1 ? "" : "s"} removed
            because the gathered evidence did not support {report.unsupported_claims_removed === 1 ? "it" : "them"}.
          </p>
        )}
        {report.engine === "rules" && (
          <p className="mt-3 text-xs text-fg-muted">
            Written from Cordon&apos;s rules; the AI investigator did not contribute
            {report.llm_status.startsWith("rejected") ? " (its answer failed verification)" : ""}.
          </p>
        )}
      </div>

      {/* Confidence */}
      <div>
        <h3 className="text-sm font-semibold text-fg">Confidence in the verdict</h3>
        {report.confidence.level === "low" && (
          <p className="mt-2 flex items-start gap-2 rounded-control border border-warning/30 bg-warning/10 p-2 text-sm text-fg">
            <AlertTriangle aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0 text-warning" />
            Low confidence: the evidence is limited. Treat this as a lead to check, not a conclusion.
          </p>
        )}
        <ul className="mt-2 list-disc pl-5 text-sm text-fg-secondary">
          {report.confidence.reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      </div>

      {/* Hypothesis */}
      <div className="rounded-control border border-dashed border-line p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge caps>Hypothesis</Badge>
          <span className="text-sm font-semibold text-fg">{report.hypothesis.label}</span>
          <span className="text-xs text-fg-muted">uncertainty: {report.hypothesis.uncertainty}</span>
        </div>
        <p className="mt-2 text-sm text-fg-secondary">
          {report.hypothesis.rationale}
          <EvidenceChips ids={report.hypothesis.evidence_ids} open={openEv} onToggle={toggle} />
        </p>
        {openEv && report.hypothesis.evidence_ids.includes(openEv) && <EvidenceText item={evidence.get(openEv)} />}
        <p className="mt-1 text-xs text-fg-muted">A working explanation of intent, not a finding.</p>
      </div>

      {/* Campaign + blast radius */}
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
            <Radar aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
            Campaign
          </h3>
          <div className="mt-2 flex items-center gap-2">
            <Badge tone={campaign.tone}>{campaign.label}</Badge>
          </div>
          <p className="mt-2 text-sm text-fg-secondary">
            {report.campaign.status === "one_off"
              ? "No other recent email in this account is linked to this one."
              : `${report.campaign.cases_in_window} linked email(s) reached ${report.campaign.recipients_in_window} recipient(s) in the last ${report.campaign.window_days} days.`}
          </p>
        </div>
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
            <Users aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
            Blast radius
          </h3>
          <p className="mt-2 text-sm text-fg-secondary">
            {report.blast_radius.recipients.length} recipient(s) received this or a linked email
            {report.blast_radius.related_case_count > 0 ? ` across ${report.blast_radius.related_case_count + 1} cases` : ""}.
          </p>
          {report.blast_radius.exposed_recipients.length > 0 && (
            <p className="mt-1 break-words text-xs text-fg-muted">
              Exposed: {report.blast_radius.exposed_recipients.join(", ")}
            </p>
          )}
        </div>
      </div>

      {/* Recommendation */}
      <div className="rounded-control border border-line bg-surface-panel p-4">
        <div className="flex flex-wrap items-center gap-2">
          <ShieldCheck aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
          <h3 className="text-sm font-semibold text-fg">Recommended action</h3>
          <Badge tone="neutral" caps>
            Not executed
          </Badge>
          {rec.suggested_tier && (
            <Badge tone="violet" title="The autonomy level that would be needed before this could run automatically">
              Suggested tier {rec.suggested_tier}
            </Badge>
          )}
        </div>
        <p className="mt-2 text-sm font-semibold text-fg">{rec.title}</p>
        {rec.secondary_actions.length > 0 && (
          <p className="text-sm text-fg-secondary">Then: {rec.secondary_actions.join(", ")}</p>
        )}
        <p className="mt-1 text-sm text-fg-secondary">{rec.rationale}</p>
      </div>

      {/* Full evidence chain */}
      <details className="text-sm">
        <summary className="flex cursor-pointer items-center gap-2 font-semibold text-fg">
          <ListChecks aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
          Evidence gathered ({investigation.evidence?.length ?? 0}) and tools used ({investigation.tool_trace?.length ?? 0})
        </summary>
        <ol className="mt-2 flex flex-col gap-1">
          {(investigation.evidence ?? []).map((e) => (
            <li key={e.id} className="text-xs text-fg-secondary">
              <span className="font-mono font-semibold text-fg">{e.id}</span> · {e.source.replace(/_/g, " ")} · {e.text}
            </li>
          ))}
        </ol>
        {investigation.tool_trace && investigation.tool_trace.length > 0 && (
          <p className="mt-2 text-xs text-fg-muted">
            Tools: {investigation.tool_trace.map((t) => t.tool.replace(/_/g, " ")).join(" → ")}
          </p>
        )}
      </details>
    </div>
  );
}
