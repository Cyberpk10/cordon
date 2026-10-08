"use client";

import { MotionConfig } from "framer-motion";
import type { ReactNode } from "react";

/**
 * App-wide motion config. `reducedMotion="user"` makes every Framer Motion animation in the
 * tree automatically skip transforms/opacity transitions for visitors with the OS-level
 * "reduce motion" preference, without each component needing its own check.
 */
export default function MotionProvider({ children }: { children: ReactNode }) {
  return <MotionConfig reducedMotion="user">{children}</MotionConfig>;
}
