import { useState, type ReactNode } from "react";
import clsx from "clsx";
import {
  AlertTriangle,
  CheckCircle2,
  MinusCircle,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import type {
  AuthResultValue,
  AuthResults,
  FrameworkControlRef,
  Severity,
  Verdict,
} from "../../types/analysis";
import { Badge, Button, Card, type BadgeTone } from "../ui";
import { VERDICT_META } from "../verdict";

/** The minimum the card needs from a fired rule — satisfied by email/chat indicators
 * directly and by intrusion findings (whose `points` map to `score`). */
export interface Signal {
  id: string;
  title: string;
  severity: Severity;
  score: number;
}

/** Strongest indicators first: score, then severity as a tie-break. */
const SEVERITY_RANK: Record<Severity, number> = { high: 3, medium: 2, low: 1 };
export function rankIndicators<T extends Signal>(indicators: T[]): T[] {
  return [...indicators].sort(
    (a, b) => b.score - a.score || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]
  );
}

/** The one-line summary under the verdict. Built only from fields the API returned —
 * the strongest indicator's own title plus a count — never invented copy. */
export function summarizeIndicators(
  verdict: Verdict,
  indicators: Signal[],
  noun: { none: string; signal: string }
): string {
  const ranked = rankIndicators(indicators);
  const n = ranked.length;
  if (n === 0) return noun.none;
  if (verdict === "safe") {
    return `${n} low-weight ${noun.signal}${n === 1 ? "" : "s"} detected — below the suspicious threshold.`;
  }
  const more = n - 1;
  return `${ranked[0].title}${more > 0 ? `, plus ${more} more ${noun.signal}${more === 1 ? "" : "s"}` : ""}.`;
}

const SEVERITY_TONE: Record<Severity, BadgeTone> = { low: "neutral", medium: "warning", high: "danger" };

const AUTH_STYLE: Record<AuthResultValue, { tone: BadgeTone; icon: LucideIcon }> = {
  pass: { tone: "success", icon: CheckCircle2 },
  fail: { tone: "danger", icon: XCircle },
  softfail: { tone: "warning", icon: AlertTriangle },
  neutral: { tone: "warning", icon: AlertTriangle },
  temperror: { tone: "warning", icon: AlertTriangle },
  permerror: { tone: "warning", icon: AlertTriangle },
  none: { tone: "neutral", icon: MinusCircle },
  unknown: { tone: "neutral", icon: MinusCircle },
};

const FRAMEWORK_LABELS: Record<string, string> = {
  mitre_attack: "MITRE ATT&CK",
  nist_csf: "NIST CSF",
  iso_27001: "ISO 27001",
  soc2: "SOC 2",
};

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-fg-muted">{children}</h3>
  );
}

function Section({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  return (
    <section className={clsx("border-t border-line px-5 py-5 sm:px-6", className)}>
      <SectionLabel>{label}</SectionLabel>
      {children}
    </section>
  );
}

export interface DetailItem {
  label: string;
  value: ReactNode;
  /** Span both columns (long values like a subject line). */
  wide?: boolean;
}

interface AnalysisResultCardProps {
  verdict: Verdict;
  score: number;
  summary: string;
  details: DetailItem[];
  /** Email only — activity logs have no SPF/DKIM/DMARC. */
  authResults?: AuthResults;
  indicators: Signal[];
  /** Id prefix of the full indicator list below the card, for "jump to details" links. */
  indicatorAnchorPrefix: string;
  indicatorsLabel?: string;
  frameworkMappings: Record<string, FrameworkControlRef[]>;
  /** Extra note under the header (e.g. "2 other incidents also detected"). */
  footnote?: ReactNode;
}

export default function AnalysisResultCard({
  verdict,
  score,
  summary,
  details,
  authResults,
  indicators,
  indicatorAnchorPrefix,
  indicatorsLabel = "Top indicators",
  frameworkMappings,
  footnote,
}: AnalysisResultCardProps) {
  const [showControlNames, setShowControlNames] = useState(false);
  const meta = VERDICT_META[verdict];
  const Icon = meta.icon;
  const top = rankIndicators(indicators).slice(0, 4);
  // Two-column facts grid: if the half-width items don't pair up evenly, stretch the last
  // one so no row ends with an empty cell.
  const halfWidth = details.filter((d) => !d.wide);
  const lastHalf = halfWidth.length % 2 === 1 ? halfWidth[halfWidth.length - 1] : null;
  const frameworks = Object.entries(frameworkMappings)
    .map(([key, refs]) => [key, Array.from(new Map(refs.map((r) => [r.control_id, r])).values())] as const)
    .filter(([, refs]) => refs.length > 0);

  return (
    <Card padding="none" aria-label={`Analysis result: ${meta.label}, risk score ${score} out of 100`} className="motion-safe:animate-[fade-in-up_200ms_ease-out]">
      {/* Verdict header */}
      <header className="flex flex-wrap items-start gap-4 px-5 py-5 sm:flex-nowrap sm:px-6 sm:py-6">
        <span
          aria-hidden="true"
          className={clsx("flex h-12 w-12 shrink-0 items-center justify-center rounded-card border", meta.tile)}
        >
          <Icon className="h-6 w-6" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">Verdict</p>
          <h2 className={clsx("text-2xl font-semibold leading-tight", meta.text)}>{meta.label}</h2>
          <p className="mt-1 text-sm text-fg-secondary">{summary}</p>
        </div>
        <div className="w-full shrink-0 sm:w-36 sm:text-right">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">Risk score</p>
          <p className="mt-0.5 leading-none">
            <span className={clsx("text-5xl font-semibold tabular-nums", meta.text)}>{score}</span>
            <span className="text-sm text-fg-muted"> / 100</span>
          </p>
          <div
            role="meter"
            aria-label="Risk score"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={score}
            className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-surface-raised"
          >
            <div className={clsx("h-full rounded-full", meta.fill)} style={{ width: `${Math.min(100, Math.max(0, score))}%` }} />
          </div>
        </div>
      </header>

      {footnote && <div className="px-5 pb-4 sm:px-6">{footnote}</div>}

      {/* Key facts */}
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 border-t border-line px-5 py-5 sm:grid-cols-2 sm:px-6">
        {details.map((item) => (
          <div key={item.label} className={clsx("min-w-0", (item.wide || item === lastHalf) && "sm:col-span-2")}>
            <dt className="text-xs text-fg-muted">{item.label}</dt>
            <dd className="mt-0.5 break-words text-sm text-fg">{item.value}</dd>
          </div>
        ))}
      </dl>

      {authResults && (
        <Section label="Email authentication">
          <ul className="grid grid-cols-3 gap-2 sm:gap-3">
            {(["spf", "dkim", "dmarc"] as const).map((key) => {
              const value = authResults[key];
              const style = AUTH_STYLE[value] ?? AUTH_STYLE.unknown;
              return (
                <li
                  key={key}
                  className="flex flex-col gap-1.5 rounded-control border border-line bg-surface-panel px-3 py-2.5 sm:flex-row sm:items-center sm:justify-between"
                >
                  <span className="text-xs font-semibold uppercase tracking-wide text-fg-secondary">{key}</span>
                  <Badge tone={style.tone} icon={style.icon} size="sm" caps>
                    {value}
                  </Badge>
                </li>
              );
            })}
          </ul>
        </Section>
      )}

      <Section label={indicatorsLabel}>
        {top.length === 0 ? (
          <p className="text-sm text-fg-secondary">Nothing fired.</p>
        ) : (
          <ol className="flex flex-col divide-y divide-line">
            {top.map((indicator) => (
              <li key={indicator.id} className="flex items-center gap-3 py-2.5 first:pt-0 last:pb-0">
                <Badge tone={SEVERITY_TONE[indicator.severity]} size="sm" caps className="w-16 justify-center">
                  {indicator.severity}
                </Badge>
                <a
                  href={`#${indicatorAnchorPrefix}${indicator.id}`}
                  className="min-w-0 flex-1 truncate text-sm text-fg underline-offset-2 hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
                >
                  {indicator.title}
                </a>
                <span className="shrink-0 text-sm font-semibold tabular-nums text-fg-secondary">
                  +{indicator.score}
                </span>
              </li>
            ))}
          </ol>
        )}
        {indicators.length > top.length && (
          <p className="mt-3 text-xs text-fg-muted">
            {indicators.length - top.length} more below in the full breakdown.
          </p>
        )}
      </Section>

      {frameworks.length > 0 && (
        <Section label="Framework mapping">
          <dl className="flex flex-col gap-3">
            {frameworks.map(([key, refs]) => (
              <div key={key} className="flex flex-col gap-1.5 sm:flex-row sm:items-start sm:gap-3">
                <dt className="shrink-0 pt-0.5 text-xs font-semibold text-fg-secondary sm:w-28">
                  {FRAMEWORK_LABELS[key] ?? key}
                </dt>
                <dd className="min-w-0 flex-1">
                  {showControlNames ? (
                    <ul className="flex flex-col gap-1 text-sm">
                      {refs.map((ref) => (
                        <li key={ref.control_id}>
                          <span className="font-mono font-semibold text-fg">{ref.control_id}</span>
                          <span className="text-fg-secondary"> — {ref.control_name}</span>
                        </li>
                      ))}
                    </ul>
                  ) : (
                    <div className="flex flex-wrap gap-1.5">
                      {refs.map((ref) => (
                        <Badge key={ref.control_id} tone="accent" size="sm" title={ref.control_name}>
                          <span className="font-mono">{ref.control_id}</span>
                          <span className="sr-only"> — {ref.control_name}</span>
                        </Badge>
                      ))}
                    </div>
                  )}
                </dd>
              </div>
            ))}
          </dl>
          <Button
            variant="link"
            className="mt-3 text-xs"
            aria-expanded={showControlNames}
            onClick={() => setShowControlNames((v) => !v)}
          >
            {showControlNames ? "Show as chips" : "Show control names"}
          </Button>
        </Section>
      )}
    </Card>
  );
}

/** Placeholder with the same silhouette as the card, shown while analysis runs. */
export function AnalysisResultSkeleton() {
  return (
    <Card padding="none" aria-busy="true" aria-label="Analyzing">
      <div className="flex items-start gap-4 px-6 py-6">
        <div className="h-12 w-12 animate-pulse rounded-card bg-surface-raised" />
        <div className="flex flex-1 flex-col gap-2">
          <div className="h-3 w-16 animate-pulse rounded bg-surface-raised" />
          <div className="h-6 w-40 animate-pulse rounded bg-surface-raised" />
          <div className="h-4 w-3/4 animate-pulse rounded bg-surface-raised" />
        </div>
        <div className="hidden w-36 flex-col items-end gap-2 sm:flex">
          <div className="h-3 w-16 animate-pulse rounded bg-surface-raised" />
          <div className="h-10 w-20 animate-pulse rounded bg-surface-raised" />
        </div>
      </div>
      {[0, 1, 2].map((i) => (
        <div key={i} className="flex flex-col gap-2 border-t border-line px-6 py-5">
          <div className="h-3 w-24 animate-pulse rounded bg-surface-raised" />
          <div className="h-4 w-full animate-pulse rounded bg-surface-raised" />
          <div className="h-4 w-2/3 animate-pulse rounded bg-surface-raised" />
        </div>
      ))}
      <span className="sr-only" role="status">
        Analyzing…
      </span>
    </Card>
  );
}
