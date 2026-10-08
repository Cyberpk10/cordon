"use client";

import { motion } from "framer-motion";

/**
 * A single annotation pointing at part of the hero panel — desktop only (xl+), where the
 * centered panel leaves enough side margin inside the page container for one without
 * crowding or risking overflow at narrower widths. See components/Hero.tsx for placement.
 */
export default function HeroCallout({
  text,
  side,
  position,
  delay = 0,
}: {
  text: string;
  side: "left" | "right";
  position: string;
  delay?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, x: side === "left" ? 12 : -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.6, delay, ease: [0.16, 1, 0.3, 1] }}
      className={`pointer-events-none absolute hidden w-44 xl:block ${position}`}
    >
      <div className={`flex items-center gap-2 ${side === "right" ? "flex-row-reverse text-right" : ""}`}>
        <span className="h-px w-6 shrink-0 bg-white/20" />
        <p className="text-xs leading-snug text-slate-400">{text}</p>
      </div>
    </motion.div>
  );
}
