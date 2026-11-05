"use client";

import { useEffect, useRef, useState, type ReactNode } from "react";
import { motion } from "framer-motion";
import {
  Loader2,
  PlayCircle,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Bot,
  FileCheck2,
} from "lucide-react";
import {
  PLAYGROUND_SAMPLES,
  type PlaygroundSample,
  type PlaygroundVerdict,
} from "@/lib/playgroundData";
import Reveal from "@/components/motion/Reveal";
import AuthChip from "@/components/ui/AuthChip";
import WindowChrome from "@/components/ui/WindowChrome";
import SectionHeading from "@/components/ui/SectionHeading";

type Status = "idle" | "analyzing" | "done";

const VERDICT_STYLES: Record<
  PlaygroundVerdict,
  { label: string; icon: typeof ShieldAlert; badge: string; ring: string }
> = {
  malicious: {
    label: "Malicious",
    icon: ShieldAlert,
    badge: "border-danger/30 bg-danger/10 text-danger",
    ring: "text-danger",
  },
  suspicious: {
    label: "Suspicious",
    icon: ShieldQuestion,
    badge: "border-warning/30 bg-warning/10 text-warning",
    ring: "text-warning",
  },
  safe: {
    label: "Safe",
    icon: ShieldCheck,
    badge: "border-success/30 bg-success/10 text-success",
    ring: "text-success",
  },
};

const SEVERITY_DOT: Record<string, string> = {
  high: "bg-danger",
  medium: "bg-warning",
  low: "bg-fg-muted",
};

// --- Tiny, purpose-built renderer for the AI analyst narrative's markdown-lite shape
// (headings, **bold**, `code`, numbered lists with a nested bullet sub-list). Not a
// general markdown parser, just enough for the exact real narratives this page ships.

function renderInline(text: string, keyPrefix: string): ReactNode[] {
  const parts: ReactNode[] = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match: RegExpExecArray | null;
  let i = 0;
  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) parts.push(text.slice(lastIndex, match.index));
    const token = match[0];
    if (token.startsWith("**")) {
      parts.push(
        <strong key={`${keyPrefix}-b${i++}`} className="font-semibold text-fg">
          {token.slice(2, -2)}
        </strong>,
      );
    } else {
      parts.push(
        <code
          key={`${keyPrefix}-c${i++}`}
          className="rounded bg-surface-raised px-1 py-0.5 font-mono text-[0.85em] text-accent-text"
        >
          {token.slice(1, -1)}
        </code>,
      );
    }
    lastIndex = match.index + token.length;
  }
  if (lastIndex < text.length) parts.push(text.slice(lastIndex));
  return parts;
}

function renderNarrative(text: string): ReactNode {
  const lines = text.split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let blockKey = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.trim() === "") {
      i++;
      continue;
    }

    if (line.startsWith("## ")) {
      blocks.push(
        <p
          key={blockKey++}
          className="mt-5 text-xs font-semibold uppercase tracking-wider text-accent-text first:mt-0"
        >
          {renderInline(line.slice(3), `h${blockKey}`)}
        </p>,
      );
      i++;
      continue;
    }

    if (line.startsWith("# ")) {
      // The narrative's own top-level title duplicates this card's heading, so it is not
      // re-rendered here, same string in lib/playgroundData.ts, just not displayed twice.
      i++;
      continue;
    }

    const isOrderedStart = /^\d+\.\s+/.test(line);
    const isBulletStart = /^-\s+/.test(line);

    if (isOrderedStart || isBulletStart) {
      const ordered = isOrderedStart;
      const items: { content: ReactNode[]; subItems: ReactNode[] }[] = [];
      while (i < lines.length) {
        const l = lines[i];
        if (l.trim() === "") {
          i++;
          continue;
        }
        const topMatch = ordered ? l.match(/^\d+\.\s+(.*)/) : l.match(/^-\s+(.*)/);
        const nestedMatch = l.match(/^\s{2,}-\s+(.*)/);
        if (topMatch) {
          items.push({ content: renderInline(topMatch[1], `li${i}`), subItems: [] });
          i++;
        } else if (nestedMatch && items.length > 0) {
          items[items.length - 1].subItems.push(
            <li key={`sub${i}`} className="list-disc text-fg-secondary">
              {renderInline(nestedMatch[1], `sub${i}`)}
            </li>,
          );
          i++;
        } else {
          break;
        }
      }
      const Tag = ordered ? "ol" : "ul";
      blocks.push(
        <Tag
          key={blockKey++}
          className={`mt-2 space-y-2 pl-5 text-sm leading-relaxed text-fg-secondary ${
            ordered ? "list-decimal" : "list-disc"
          }`}
        >
          {items.map((item, idx) => (
            <li key={idx}>
              {item.content}
              {item.subItems.length > 0 && (
                <ul className="mt-1 space-y-1 pl-5 text-xs">{item.subItems}</ul>
              )}
            </li>
          ))}
        </Tag>,
      );
      continue;
    }

    const paraLines: string[] = [];
    while (
      i < lines.length &&
      lines[i].trim() !== "" &&
      !lines[i].startsWith("#") &&
      !/^\d+\.\s+/.test(lines[i]) &&
      !/^-\s+/.test(lines[i])
    ) {
      paraLines.push(lines[i]);
      i++;
    }
    blocks.push(
      <p key={blockKey++} className="mt-3 text-sm leading-relaxed text-fg-secondary first:mt-0">
        {renderInline(paraLines.join(" "), `p${blockKey}`)}
      </p>,
    );
  }

  return <div>{blocks}</div>;
}

function ResultCard({ sample }: { sample: PlaygroundSample }) {
  const style = VERDICT_STYLES[sample.verdict];
  const Icon = style.icon;

  return (
    <div className="card p-6 sm:p-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className={`inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-semibold uppercase tracking-wider ${style.badge}`}>
          <Icon className="h-4 w-4" />
          {style.label}
        </div>
        <div className="text-right">
          <p className="text-xs font-semibold uppercase tracking-wider text-fg-muted">Risk score</p>
          <p className={`text-2xl font-semibold ${style.ring}`}>{sample.score}/100</p>
        </div>
      </div>

      <div className="mt-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
          Indicators detected ({sample.indicators.length})
        </p>
        <ul className="mt-3 space-y-3">
          {sample.indicators.map((ind) => (
            <li key={ind.id} className="flex items-start gap-3">
              <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${SEVERITY_DOT[ind.severity]}`} />
              <div>
                <p className="text-sm font-semibold text-fg">{ind.title}</p>
                <p className="mt-0.5 text-sm leading-relaxed text-fg-secondary">{ind.description}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-6">
        <p className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
          Authentication results
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <AuthChip label="SPF" result={sample.auth.spf} />
          <AuthChip label="DKIM" result={sample.auth.dkim} />
          <AuthChip label="DMARC" result={sample.auth.dmarc} />
        </div>
      </div>

      <div className="mt-6">
        <div className="flex items-center gap-2">
          <FileCheck2 className="h-4 w-4 text-accent-text" />
          <p className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
            Compliance framework mapping
          </p>
        </div>
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          {sample.frameworks
            .filter((fw) => fw.controls.length > 0)
            .map((fw) => (
              <div key={fw.key}>
                <p className="text-xs font-semibold text-fg-secondary">{fw.label}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {fw.controls.map((c) => (
                    <span
                      key={c.id}
                      title={c.name}
                      className="inline-flex items-center rounded border border-line bg-surface-raised/70 px-2 py-1 font-mono text-[11px] font-normal text-fg-secondary"
                    >
                      {c.id}
                    </span>
                  ))}
                </div>
              </div>
            ))}
        </div>
      </div>

      <div className="mt-6 rounded-card border border-line bg-surface-panel p-5">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-accent-text" />
          <p className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
            AI analyst summary
          </p>
        </div>
        {renderNarrative(sample.narrative)}
        <p className="mt-4 border-t border-line/60 pt-3 text-[11px] text-fg-muted">
          Narrative generated by {sample.analystModel}. It explains the score above and never
          changes it.
        </p>
      </div>
    </div>
  );
}

function AnalyzingPanel() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 card p-16 text-center">
      <Loader2 className="h-8 w-8 animate-spin text-accent-text" />
      <p className="text-sm font-normal text-fg-secondary">
        Analyzing headers, links, and authentication results...
      </p>
    </div>
  );
}

function IdlePanel({ onAnalyze }: { onAnalyze: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-5 rounded-card border border-dashed border-line-strong bg-surface-card p-16 text-center">
      <p className="max-w-xs text-sm text-fg-secondary">
        This email has not been analyzed yet. Click below to run it through Cordon.
      </p>
      <button
        type="button"
        onClick={onAnalyze}
        className="btn btn-primary btn-lg"
      >
        <PlayCircle className="h-4 w-4" />
        Analyze this email
      </button>
    </div>
  );
}

export default function EmailPlayground() {
  const [selectedKey, setSelectedKey] = useState<PlaygroundSample["key"]>(
    PLAYGROUND_SAMPLES[0].key,
  );
  const [status, setStatus] = useState<Status>("idle");
  const timeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const sample = PLAYGROUND_SAMPLES.find((s) => s.key === selectedKey)!;

  function selectSample(key: PlaygroundSample["key"]) {
    if (key === selectedKey) return;
    setSelectedKey(key);
    setStatus("idle");
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
  }

  function runAnalysis() {
    setStatus("analyzing");
    timeoutRef.current = setTimeout(() => setStatus("done"), 1300);
  }

  return (
    <section id="playground" className="bg-surface-panel section-y">
      <div className="mx-auto max-w-6xl px-6">
        <Reveal className="mx-auto max-w-2xl text-center">
          <SectionHeading
            title={<>Try it on a real email</>}
            lede={<>Pick a sample email below and click Analyze to watch Cordon&rsquo;s real verdict render.</>}
          />
        </Reveal>

        <Reveal delay={0.1} className="mt-12 grid gap-3 sm:grid-cols-3">
          {PLAYGROUND_SAMPLES.map((s) => {
            const isSelected = s.key === selectedKey;
            const vStyle = VERDICT_STYLES[s.verdict];
            const VIcon = vStyle.icon;
            return (
              <button
                key={s.key}
                type="button"
                onClick={() => selectSample(s.key)}
                className={`rounded-card border px-5 py-4 text-left transition-[background-color,border-color,transform] duration-150 ${
                  isSelected
                    ? "border-accent/50 bg-surface-raised"
                    : "border-line bg-surface-card hover:-translate-y-0.5 hover:border-line-strong hover:bg-surface-raised/50"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-fg">{s.label}</span>
                  <VIcon className={`h-4 w-4 ${vStyle.ring}`} />
                </div>
                <p className="mt-1.5 truncate text-xs text-fg-secondary">{s.email.subject}</p>
              </button>
            );
          })}
        </Reveal>

        <Reveal delay={0.15} y={28} className="mt-8 grid gap-6 lg:grid-cols-2 lg:items-start">
          <div className="card overflow-hidden">
            <WindowChrome title="Inbox preview" />
            <div className="space-y-2 border-b border-line px-6 py-5 text-sm">
              <p className="text-fg-secondary">
                <span className="text-fg-muted">From: </span>
                <span className="text-fg">
                  {sample.email.fromDisplay} &lt;{sample.email.fromAddress}&gt;
                </span>
              </p>
              <p className="text-fg-secondary">
                <span className="text-fg-muted">To: </span>
                <span className="text-fg">{sample.email.to}</span>
              </p>
              <p className="text-fg-secondary">
                <span className="text-fg-muted">Subject: </span>
                <span className="font-normal text-fg">{sample.email.subject}</span>
              </p>
            </div>
            <div className="whitespace-pre-line px-6 py-5 text-sm leading-relaxed text-fg-secondary">
              {sample.email.body}
            </div>
          </div>

          <div key={status === "done" ? sample.key : "pending"}>
            {status === "idle" && <IdlePanel onAnalyze={runAnalysis} />}
            {status === "analyzing" && <AnalyzingPanel />}
            {status === "done" && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
                className="space-y-4"
              >
                <ResultCard sample={sample} />
                <button
                  type="button"
                  onClick={runAnalysis}
                  className="inline-flex items-center gap-2 rounded-control text-sm text-fg-secondary transition-colors duration-150 hover:text-fg focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-accent-text"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  Run the analysis again
                </button>
              </motion.div>
            )}
          </div>
        </Reveal>

        <p className="mx-auto mt-10 max-w-xl text-center text-xs text-fg-muted">
          Real Cordon analysis on curated sample emails. Live, paste-your-own analysis is
          coming soon.
        </p>
      </div>
    </section>
  );
}
