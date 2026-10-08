"use client";

import { motion } from "framer-motion";
import type { ReactNode } from "react";

/**
 * Shared scroll-triggered reveal: fade + slight rise, once per element. Kept to a single
 * easing/duration everywhere so the whole site feels like one system, not a pile of one-off
 * animations. Respects prefers-reduced-motion via MotionProvider's app-wide MotionConfig.
 */
export default function Reveal({
  children,
  delay = 0,
  y = 20,
  className,
  as = "div",
}: {
  children: ReactNode;
  delay?: number;
  y?: number;
  className?: string;
  as?: "div" | "li";
}) {
  const Component = as === "li" ? motion.li : motion.div;
  return (
    <Component
      className={className}
      initial={{ opacity: 0, y }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true, margin: "-80px" }}
      transition={{ duration: 0.6, delay, ease: [0.16, 1, 0.3, 1] }}
    >
      {children}
    </Component>
  );
}
