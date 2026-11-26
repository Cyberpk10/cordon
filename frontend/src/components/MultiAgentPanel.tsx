import { useCallback, useEffect, useRef, useState } from "react";
import { ArrowDown, ArrowUp, Network, RefreshCw } from "lucide-react";
import { getCaseMultiAgent, runCaseMultiAgent } from "../api/client";
import type {
  MultiAgentAssessment,
  MultiAgentContribution,
  MultiAgentFinding,
} from "../types/analysis";
import { Badge, Button, Card, ErrorState, LoadingState, type BadgeTone } from "./ui";

const STANCE: Record<MultiAgentContribution["stance"], { label: string; tone: BadgeTone }> = {
  supports_threat: { label: "Supports threat", tone: "danger" },
  supports_benign: { label: "Supports benign", tone: "success" },
  neutral: { label: "Neutral", tone: "neutral" },
};
const STATUS_TONE: Record<MultiAgentContribution["status"], BadgeTone> = {
  ok: "neutral",
  no_data: "neutral",
  error: "danger",
  skipped: "warning",
};
const VERDICT_TONE: Record<string, BadgeTone> = { safe: "success", suspicious: "warning", malicious: "danger" };
const CONF_TONE: Record<string, BadgeTone> = { high: "success", medium: "warning", low: "neutral" };

/** Strip the <untrusted> delimiters for display; the text inside stays plain text (React escapes it). */
function display(text: string): string {
  return text.replace(/<\/?untrusted>/g, "");
}

function IdChip({ id, onJump }: { id: string; onJump: (id: string) => void }) {
  return (
    <button
      type="button"
      onClick={() => onJump(id)}
      className="rounded border border-line bg-surface-raised px-1.5 py-0.5 font-mono text-[11px] text-fg-secondary hover:border-accent hover:text-accent"
      title={`Show finding ${id}`}
    >
      {id}
    </button>
  );
}

function FindingRow({
  finding,
  highlighted,
  onJump,
}: {
  finding: MultiAgentFinding;
  highlighted: boolean;
  onJump: (id: string) => void;
}) {
  return (
    <li
      id={`ma-${finding.id}`}
      className={`flex flex-col gap-1 rounded-md px-2 py-1.5 transition-colors ${highlighted ? "bg-accent/10 ring-1 ring-accent" : ""}`}
    >
      <div className="flex items-start gap-2">
        <span className="mt-0.5 shrink-0 font-mono text-[11px] font-semibold text-fg-muted">{finding.id}</span>
        <span className="min-w-0 break-words text-sm text-fg">{display(finding.text)}</span>
      </div>
      {finding.refs.length > 0 && (
        <div className="ml-10 flex flex-wrap items-center gap-1 text-[11px] text-fg-muted">
          used:
          {finding.refs.map((r) => (
            <IdChip key={r} id={r} onJump={onJump} />
          ))}
        </div>
      )}
    </li>
  );
}

/** D6: each agent's input and the consolidated synthesis for one case. Recommend-only. */
export default function MultiAgentPanel({ caseId }: { caseId: string }) {
  const [data, setData] = useState<MultiAgentAssessment | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const [highlight, setHighlight] = useState<string | null>(null);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    let cancelled = false;
    setData(null);
    setError(null);
    getCaseMultiAgent(caseId)
      .then((d) => !cancelled && setData(d))
      .catch((err) => !cancelled && setError(err instanceof Error ? err.message : "Failed to load the multi-agent view."));
    return () => {
      cancelled = true;
    };
  }, [caseId]);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const jump = useCallback((id: string) => {
    document.getElementById(`ma-${id}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
    setHighlight(id);
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setHighlight(null), 2000);
  }, []);

  const rerun = async () => {
    setRunning(true);
    setError(null);
    try {
      setData(await runCaseMultiAgent(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to re-run.");
    } finally {
      setRunning(false);
    }
  };

  if (!data) {
    return <Card>{error ? <ErrorState message={error} /> : <LoadingState label="Loading multi-agent view…" lines={3} />}</Card>;
  }

  const syn = data.synthesis;
  const conf = syn.confidence;
  const rec = syn.recommended_action;
  const summaries = Object.fromEntries(data.narrative.agent_summaries.map((s) => [s.agent, s]));

  return (
    <Card>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
          <Network aria-hidden="true" className="h-4 w-4 text-accent" />
          Multi-agent view
        </h2>
        <div className="flex items-center gap-2">
          <Badge size="sm" tone={data.engine === "llm" ? "violet" : "neutral"} title={`Wording: ${data.llm_status}`}>
            {data.engine === "llm" ? "AI-written" : "Rules"}
          </Badge>
          <Button size="sm" variant="secondary" icon={RefreshCw} loading={running} onClick={rerun}>
            Re-run
          </Button>
        </div>
      </div>
      <p className="mt-1 text-sm text-fg-secondary">
        Five agents read this case in turn, each building on the earlier ones. The decision below is computed
        from their findings; nothing here takes an action.
      </p>
      {error && <ErrorState message={error} className="mt-3" />}

      {/* synthesis */}
      <div className="mt-4 rounded-lg border border-line bg-surface-raised p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={VERDICT_TONE[syn.verdict] ?? "neutral"}>
            {syn.verdict} · {syn.score}/100
          </Badge>
          <Badge tone={CONF_TONE[conf.level]} title={conf.reasons.join(" ") || undefined}>
            Confidence {conf.level}
            {conf.change > 0 && <ArrowUp aria-label="raised" className="ml-1 inline h-3 w-3" />}
            {conf.change < 0 && <ArrowDown aria-label="lowered" className="ml-1 inline h-3 w-3" />}
          </Badge>
          <Badge tone="neutral">{syn.hypothesis.label}</Badge>
          {syn.escalation_advised && <Badge tone="danger">Escalation advised</Badge>}
        </div>
        {conf.change !== 0 && (
          <p className="mt-2 text-xs text-fg-muted">
            {conf.change > 0 ? "Raised" : "Lowered"} from {conf.base_level}: {conf.reasons.join(" ")}
          </p>
        )}
        <p className="mt-2 text-sm text-fg">
          <span className="font-semibold">Recommended:</span> {rec.title}
          {rec.suggested_tier && <span className="text-fg-muted"> (tier {rec.suggested_tier})</span>}
        </p>
        <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-fg-secondary">
          {syn.would_d5_act.summary}
          {syn.would_d5_act.mode === "shadow" && (
            <Badge size="sm" tone="violet">
              Shadow mode
            </Badge>
          )}
        </p>
        {syn.conflicts.length > 0 && (
          <ul className="mt-3 flex flex-col gap-2">
            {syn.conflicts.map((c) => (
              <li key={c.id} className="rounded-md border border-line px-2.5 py-2 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] text-fg-muted">{c.id}</span>
                  <span className="font-semibold text-fg">{c.title}</span>
                  {c.refs.slice(0, 6).map((r) => (
                    <IdChip key={r} id={r} onJump={jump} />
                  ))}
                </div>
                <p className="mt-1 text-fg-secondary">{c.resolution}</p>
              </li>
            ))}
          </ul>
        )}
        <div className="mt-3 border-t border-line pt-3 text-sm text-fg">
          {display(data.narrative.synthesis.text)}
          <span className="ml-1 inline-flex flex-wrap gap-1 align-middle">
            {data.narrative.synthesis.finding_ids.slice(0, 8).map((id) => (
              <IdChip key={id} id={id} onJump={jump} />
            ))}
          </span>
        </div>
      </div>

      {/* agents */}
      <ol className="mt-4 flex flex-col gap-3">
        {data.agents.map((a, i) => (
          <li key={`${a.agent}-${a.round}-${i}`} className="rounded-lg border border-line p-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-sm font-semibold text-fg">{a.label}</span>
              {a.round === 2 && (
                <Badge size="sm" tone="accent" title={`Cross-check requested by conflict ${a.cross_check_of}`}>
                  Cross-check · {a.cross_check_of}
                </Badge>
              )}
              {a.status === "ok" ? (
                <Badge size="sm" tone={STANCE[a.stance].tone}>
                  {STANCE[a.stance].label} · {a.weight}
                </Badge>
              ) : (
                <Badge size="sm" tone={STATUS_TONE[a.status]}>
                  {a.status.replace("_", " ")}
                </Badge>
              )}
            </div>
            {a.round === 1 && summaries[a.agent] && (
              <p className="mt-1 text-sm text-fg-secondary">{display(summaries[a.agent].text)}</p>
            )}
            {a.round !== 1 && a.summary && <p className="mt-1 text-sm text-fg-secondary">{a.summary}</p>}
            {a.findings.length > 0 && (
              <ul className="mt-2 flex flex-col gap-0.5">
                {a.findings.map((f) => (
                  <FindingRow key={f.id} finding={f} highlighted={highlight === f.id} onJump={jump} />
                ))}
              </ul>
            )}
          </li>
        ))}
      </ol>

      <p className="mt-3 text-xs text-fg-muted">
        {data.usage.rounds} round{data.usage.rounds === 1 ? "" : "s"} · {data.usage.steps} agent steps ·{" "}
        {data.usage.llm_calls} AI call{data.usage.llm_calls === 1 ? "" : "s"}
        {data.usage.tokens > 0 && ` · ${data.usage.tokens} tokens · ~$${data.usage.est_cost_usd.toFixed(4)}`}
        {data.stop_reason && ` · stopped: ${data.stop_reason}`}
        {data.engine === "rules" && data.llm_status !== "not_requested" && ` · AI wording: ${data.llm_status}`}
      </p>
    </Card>
  );
}
