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
  CheckCircle2,
  XCircle,
  Bot,
  FileCheck2,
} from "lucide-react";
import {
  PLAYGROUND_SAMPLES,
  type PlaygroundSample,
  type PlaygroundVerdict,
} from "@/lib/playgroundData";
import Reveal from "@/components/motion/Reveal";

type Status = "idle" | "analyzing" | "done";

const VERDICT_STYLES: Record<
  PlaygroundVerdict,
  { label: string; icon: typeof ShieldAlert; badge: string; ring: string }
> = {
  malicious: {
    label: "Malicious",
    icon: ShieldAlert,
    badge: "border-red-500/30 bg-red-500/10 text-red-400",
    ring: "text-red-400",
  },
  suspicious: {
    label: "Suspicious",
    icon: ShieldQuestion,
    badge: "border-yellow-500/30 bg-yellow-500/10 text-yellow-400",
    ring: "text-yellow-400",
  },
  safe: {
    label: "Safe",
    icon: ShieldCheck,
    badge: "border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
    ring: "text-emerald-400",
  },
};

const SEVERITY_DOT: Record<string, string> = {
  high: "bg-red-400",
  medium: "bg-yellow-400",
  low: "bg-slate-500",
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
        <strong key={`${keyPrefix}-b${i++}`} className="font-semibold text-white">
          {token.slice(2, -2)}
        </strong>,
      );
    } else {
      parts.push(
        <code
          key={`${keyPrefix}-c${i++}`}
          className="rounded bg-white/10 px-1 py-0.5 font-mono text-[0.85em] text-brand-blue"
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
          className="mt-5 text-xs font-bold uppercase tracking-wide text-brand-blue first:mt-0"
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
            <li key={`sub${i}`} className="list-disc text-slate-400">
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
          className={`mt-2 space-y-2 pl-5 text-sm leading-relaxed text-slate-300 ${
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
      <p key={blockKey++} className="mt-3 text-sm leading-relaxed text-slate-300 first:mt-0">
        {renderInline(paraLines.join(" "), `p${blockKey}`)}
      </p>,
    );
  }

  return <div>{blocks}</div>;
}

function AuthChip({ label, result }: { label: string; result: string }) {
  const pass = result === "pass";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-semibold ${
        pass
          ? "border-emerald-500/20 bg-emerald-500/5 text-emerald-400"
          : "border-red-500/20 bg-red-500/5 text-red-400"
      }`}
    >
      {pass ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
      {label}: {result}
    </span>
  );
}

function ResultCard({ sample }: { sample: PlaygroundSample }) {
  const style = VERDICT_STYLES[sample.verdict];
  const Icon = style.icon;

  return (
    <div className="rounded-2xl border border-white/10 bg-navy-950 p-6 sm:p-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div className={`inline-flex items-center gap-2 rounded-full border px-4 py-1.5 text-sm font-bold uppercase tracking-wide ${style.badge}`}>
          <Icon className="h-4 w-4" />
          {style.label}
        </div>
        <div className="text-right">
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">Risk score</p>
          <p className={`text-2xl font-bold ${style.ring}`}>{sample.score}/100</p>
        </div>
      </div>

      <div className="mt-6">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Indicators detected ({sample.indicators.length})
        </p>
        <ul className="mt-3 space-y-3">
          {sample.indicators.map((ind) => (
            <li key={ind.id} className="flex items-start gap-3">
              <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${SEVERITY_DOT[ind.severity]}`} />
              <div>
                <p className="text-sm font-semibold text-white">{ind.title}</p>
                <p className="mt-0.5 text-sm leading-relaxed text-slate-400">{ind.description}</p>
              </div>
            </li>
          ))}
        </ul>
      </div>

      <div className="mt-6">
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
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
          <FileCheck2 className="h-4 w-4 text-brand-blue" />
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Compliance framework mapping
          </p>
        </div>
        <div className="mt-3 grid gap-4 sm:grid-cols-2">
          {sample.frameworks
            .filter((fw) => fw.controls.length > 0)
            .map((fw) => (
              <div key={fw.key}>
                <p className="text-xs font-semibold text-slate-400">{fw.label}</p>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {fw.controls.map((c) => (
                    <span
                      key={c.id}
                      title={c.name}
                      className="inline-flex items-center rounded border border-white/10 bg-white/5 px-2 py-1 font-mono text-[11px] font-medium text-slate-300"
                    >
                      {c.id}
                    </span>
                  ))}
                </div>
              </div>
            ))}
        </div>
      </div>

      <div className="mt-6 rounded-xl border border-white/10 bg-navy-900 p-5">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-brand-blue" />
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            AI analyst summary
          </p>
        </div>
        {renderNarrative(sample.narrative)}
        <p className="mt-4 border-t border-white/5 pt-3 text-[11px] text-slate-600">
          Narrative generated by {sample.analystModel}. It explains the score above and never
          changes it.
        </p>
      </div>
    </div>
  );
}

function AnalyzingPanel() {
  return (
    <div className="flex flex-col items-center justify-center gap-4 rounded-2xl border border-white/10 bg-navy-950 p-16 text-center">
      <Loader2 className="h-8 w-8 animate-spin text-brand-blue" />
      <p className="text-sm font-medium text-slate-300">
        Analyzing headers, links, and authentication results...
      </p>
    </div>
  );
}

function IdlePanel({ onAnalyze }: { onAnalyze: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-5 rounded-2xl border border-dashed border-white/15 bg-navy-950 p-16 text-center">
      <p className="max-w-xs text-sm text-slate-400">
        This email has not been analyzed yet. Click below to run it through Cordon.
      </p>
      <button
        type="button"
        onClick={onAnalyze}
        className="btn-primary inline-flex items-center gap-2 rounded-md px-6 py-3 text-sm font-semibold text-white"
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
    <section id="playground" className="bg-navy-900 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <Reveal className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Try it on a real email
          </h2>
          <p className="mt-4 text-lg text-slate-400">
            Pick a sample email below and click Analyze to watch Cordon&rsquo;s real verdict
            render.
          </p>
        </Reveal>

        <Reveal delay={0.1} className="mt-10 grid gap-3 sm:grid-cols-3">
          {PLAYGROUND_SAMPLES.map((s) => {
            const isSelected = s.key === selectedKey;
            const vStyle = VERDICT_STYLES[s.verdict];
            const VIcon = vStyle.icon;
            return (
              <button
                key={s.key}
                type="button"
                onClick={() => selectSample(s.key)}
                className={`rounded-xl border px-5 py-4 text-left transition-all duration-200 ${
                  isSelected
                    ? "border-brand-blue/50 bg-navy-800"
                    : "border-white/10 bg-navy-950 hover:-translate-y-0.5 hover:border-white/20 hover:bg-navy-800/50"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm font-semibold text-white">{s.label}</span>
                  <VIcon className={`h-4 w-4 ${vStyle.ring}`} />
                </div>
                <p className="mt-1.5 truncate text-xs text-slate-500">{s.email.subject}</p>
              </button>
            );
          })}
        </Reveal>

        <Reveal delay={0.15} y={28} className="mt-8 grid gap-6 lg:grid-cols-2 lg:items-start">
          <div className="overflow-hidden rounded-2xl border border-white/10 bg-navy-950 transition-colors duration-300 hover:border-white/15">
            <div className="flex items-center gap-1.5 border-b border-white/10 bg-navy-900 px-5 py-3">
              <span className="h-2.5 w-2.5 rounded-full bg-slate-700" />
              <span className="h-2.5 w-2.5 rounded-full bg-slate-700" />
              <span className="h-2.5 w-2.5 rounded-full bg-slate-700" />
              <span className="ml-2 text-xs font-medium text-slate-500">Inbox preview</span>
            </div>
            <div className="space-y-2 border-b border-white/10 px-6 py-5 text-sm">
              <p className="text-slate-400">
                <span className="text-slate-600">From: </span>
                <span className="text-slate-200">
                  {sample.email.fromDisplay} &lt;{sample.email.fromAddress}&gt;
                </span>
              </p>
              <p className="text-slate-400">
                <span className="text-slate-600">To: </span>
                <span className="text-slate-200">{sample.email.to}</span>
              </p>
              <p className="text-slate-400">
                <span className="text-slate-600">Subject: </span>
                <span className="font-medium text-white">{sample.email.subject}</span>
              </p>
            </div>
            <div className="whitespace-pre-line px-6 py-5 text-sm leading-relaxed text-slate-300">
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
                  className="inline-flex items-center gap-2 text-sm font-medium text-slate-400 transition-colors hover:text-white"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  Run the analysis again
                </button>
              </motion.div>
            )}
          </div>
        </Reveal>

        <p className="mx-auto mt-10 max-w-xl text-center text-xs text-slate-500">
          Real Cordon analysis on curated sample emails. Live, paste-your-own analysis is
          coming soon.
        </p>
      </div>
    </section>
  );
}
