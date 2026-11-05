"use client";

import { motion, type Variants } from "framer-motion";
import {
  ShieldAlert,
  CheckCircle2,
  FileCheck2,
} from "lucide-react";
import { PLAYGROUND_SAMPLES } from "@/lib/playgroundData";
import AuthChip from "@/components/ui/AuthChip";
import WindowChrome from "@/components/ui/WindowChrome";

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

export default function HeroPanel() {
  return (
    <motion.div
      initial="hidden"
      animate="visible"
      variants={container}
      className="overflow-hidden rounded-card border border-line bg-surface-card/95 shadow-[0_30px_80px_-20px_rgba(0,0,0,0.7)] backdrop-blur-sm"
    >
      <WindowChrome
        title="Case review"
        right={
          <span className="inline-flex items-center gap-1.5 text-[11px] text-fg-muted">
            <span aria-hidden className="relative flex h-1.5 w-1.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-danger opacity-75" />
              <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-danger" />
            </span>
            Live verdict
          </span>
        }
      />

      <div className="px-5 py-6 sm:px-7 sm:py-7">
        {/* Sender / subject */}
        <motion.div variants={row} className="space-y-1 border-b border-line/60 pb-5 text-sm">
          <p className="text-fg-muted">
            From <span className="text-fg-secondary">{sample.email.fromDisplay}</span>{" "}
            <span className="font-mono text-xs text-fg-muted">
              &lt;{sample.email.fromAddress}&gt;
            </span>
          </p>
          <p className="font-normal text-fg">{sample.email.subject}</p>
        </motion.div>

        {/* Verdict + score */}
        <motion.div
          variants={row}
          className="mt-5 flex flex-wrap items-center justify-between gap-4"
        >
          <div className="inline-flex items-center gap-2 rounded-full border border-danger/30 bg-danger/10 px-4 py-1.5 text-sm font-semibold uppercase tracking-wider text-danger">
            <ShieldAlert className="h-4 w-4" />
            Malicious
          </div>
          <div className="text-right">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">
              Risk score
            </p>
            <p className="font-display text-3xl font-semibold text-danger">
              {sample.score}
              <span className="text-base font-semibold text-fg-muted">/100</span>
            </p>
          </div>
        </motion.div>

        {/* Top indicators */}
        <motion.div variants={row} className="mt-6">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">
            Top indicators ({sample.indicators.length} total)
          </p>
          <ul className="mt-3 space-y-2.5">
            {topIndicators.map((ind) => (
              <li key={ind.id} className="flex items-start gap-2.5">
                <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-danger" />
                <span className="text-sm font-normal text-fg">{ind.title}</span>
              </li>
            ))}
          </ul>
          <div className="mt-3 flex flex-wrap gap-2">
            <AuthChip label="SPF" result={sample.auth.spf} size="sm" />
            <AuthChip label="DKIM" result={sample.auth.dkim} size="sm" />
            <AuthChip label="DMARC" result={sample.auth.dmarc} size="sm" />
          </div>
        </motion.div>

        {/* Frameworks */}
        <motion.div variants={row} className="mt-6 border-t border-line/60 pt-5">
          <div className="flex items-center gap-2">
            <FileCheck2 className="h-3.5 w-3.5 text-accent-text" />
            <p className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">
              Mapped to compliance frameworks
            </p>
          </div>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {sample.frameworks.map((fw) => (
              <span
                key={fw.key}
                title={fw.controls[0]?.name}
                className="inline-flex items-center gap-1 rounded-control border border-line bg-surface-raised/70 px-2.5 py-1 text-[11px] font-normal text-fg-secondary"
              >
                <CheckCircle2 className="h-3 w-3 text-accent-text" />
                {fw.label}
                {fw.controls[0] && (
                  <span className="font-mono text-fg-secondary">{fw.controls[0].id}</span>
                )}
              </span>
            ))}
          </div>
        </motion.div>
      </div>
    </motion.div>
  );
}
