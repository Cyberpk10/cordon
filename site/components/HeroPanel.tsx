"use client";

import { motion, type Variants } from "framer-motion";
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  FileCheck2,
} from "lucide-react";
import { PLAYGROUND_SAMPLES } from "@/lib/playgroundData";

// The hero's product panel is not a mockup: every field below is read straight off the real
// PayPal credential-phishing sample in lib/playgroundData.ts (captured from an actual Cordon
// analyzer response — see that file's docstring). Only a representative subset of the 9 real
// indicators is shown, chosen by score, to keep a hero-sized panel legible.
const sample = PLAYGROUND_SAMPLES.find((s) => s.key === "phishing")!;
const topIndicators = [...sample.indicators]
  .sort((a, b) => b.score - a.score)
  .slice(0, 3);

const container: Variants = {
  hidden: {},
  visible: { transition: { staggerChildren: 0.09, delayChildren: 0.3 } },
};

const row: Variants = {
  hidden: { opacity: 0, y: 12 },
  visible: { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } },
};

function AuthChip({ label }: { label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 rounded-md border border-red-500/20 bg-red-500/5 px-2.5 py-1 text-[11px] font-semibold text-red-400">
      <XCircle className="h-3 w-3" />
      {label}: fail
    </span>
  );
}

export default function HeroPanel() {
  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={container}
      className="overflow-hidden rounded-2xl border border-white/10 bg-navy-900/90 shadow-[0_30px_80px_-20px_rgba(0,0,0,0.7)] backdrop-blur-sm"
    >
      {/* Chrome bar */}
      <div className="flex items-center gap-2 border-b border-white/10 bg-white/[0.02] px-5 py-3.5">
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="h-2.5 w-2.5 rounded-full bg-white/15" />
        <span className="ml-2 text-xs font-medium text-slate-500">Case review</span>
        <span className="ml-auto inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-500">
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-red-500" />
          </span>
          Live verdict
        </span>
      </div>

      <div className="px-5 py-6 sm:px-7 sm:py-7">
        {/* Sender / subject */}
        <motion.div variants={row} className="space-y-1 border-b border-white/5 pb-5 text-sm">
          <p className="text-slate-500">
            From <span className="text-slate-300">{sample.email.fromDisplay}</span>{" "}
            <span className="font-mono text-xs text-slate-600">
              &lt;{sample.email.fromAddress}&gt;
            </span>
          </p>
          <p className="font-medium text-white">{sample.email.subject}</p>
        </motion.div>

        {/* Verdict + score */}
        <motion.div
          variants={row}
          className="mt-5 flex flex-wrap items-center justify-between gap-4"
        >
          <div className="inline-flex items-center gap-2 rounded-full border border-red-500/30 bg-red-500/10 px-4 py-1.5 text-sm font-bold uppercase tracking-wide text-red-400">
            <ShieldAlert className="h-4 w-4" />
            Malicious
          </div>
          <div className="text-right">
            <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
              Risk score
            </p>
            <p className="font-display text-3xl font-bold text-red-400">
              {sample.score}
              <span className="text-base font-semibold text-slate-500">/100</span>
            </p>
          </div>
        </motion.div>

        {/* Top indicators */}
        <motion.div variants={row} className="mt-6">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
            Top indicators ({sample.indicators.length} total)
          </p>
          <ul className="mt-3 space-y-2.5">
            {topIndicators.map((ind) => (
              <li key={ind.id} className="flex items-start gap-2.5">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-red-400" />
                <span className="text-sm font-medium text-slate-200">{ind.title}</span>
              </li>
            ))}
          </ul>
          <div className="mt-3 flex flex-wrap gap-2">
            <AuthChip label="SPF" />
            <AuthChip label="DKIM" />
            <AuthChip label="DMARC" />
          </div>
        </motion.div>

        {/* Frameworks */}
        <motion.div variants={row} className="mt-6 border-t border-white/5 pt-5">
          <div className="flex items-center gap-2">
            <FileCheck2 className="h-3.5 w-3.5 text-brand-blue" />
            <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-500">
              Mapped to compliance frameworks
            </p>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {sample.frameworks.map((fw) => (
              <span
                key={fw.key}
                title={fw.controls[0]?.name}
                className="inline-flex items-center gap-1 rounded-md border border-white/10 bg-white/5 px-2.5 py-1 text-[11px] font-medium text-slate-300"
              >
                <CheckCircle2 className="h-3 w-3 text-brand-blue" />
                {fw.label}
                {fw.controls[0] && (
                  <span className="font-mono text-slate-500">{fw.controls[0].id}</span>
                )}
              </span>
            ))}
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}
