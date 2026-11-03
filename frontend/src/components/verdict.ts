import { ShieldAlert, ShieldCheck, ShieldX, type LucideIcon } from "lucide-react";
import type { Verdict } from "../types/analysis";
import type { BadgeTone } from "./ui";

/** One source of truth for how each verdict looks, shared by VerdictBadge, the Analyze
 * result card, and anything else that colour-codes a verdict or risk score. */
export const VERDICT_META: Record<
  Verdict,
  { label: string; tone: BadgeTone; icon: LucideIcon; text: string; fill: string; tile: string }
> = {
  safe: {
    label: "Safe",
    tone: "success",
    icon: ShieldCheck,
    text: "text-success",
    fill: "bg-success",
    tile: "border-success/35 bg-success/10 text-success",
  },
  suspicious: {
    label: "Suspicious",
    tone: "warning",
    icon: ShieldAlert,
    text: "text-warning",
    fill: "bg-warning",
    tile: "border-warning/35 bg-warning/10 text-warning",
  },
  malicious: {
    label: "Malicious",
    tone: "danger",
    icon: ShieldX,
    text: "text-danger",
    fill: "bg-danger",
    tile: "border-danger/35 bg-danger/10 text-danger",
  },
};
