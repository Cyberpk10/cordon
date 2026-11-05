import { Layers, Undo2, ShieldOff, Power, ScrollText } from "lucide-react";
import Reveal from "@/components/motion/Reveal";

const BADGES = [
  { icon: Layers, label: "Graduated levels (L0-L3)" },
  { icon: Undo2, label: "Reversible-first actions" },
  { icon: ShieldOff, label: "Executive exclusions" },
  { icon: Power, label: "Kill switch" },
  { icon: ScrollText, label: "Full audit trail" },
];

export default function AutonomyBand() {
  return (
    <section id="autonomy" className="border-y border-line/60 bg-surface-panel py-24">
      <Reveal className="mx-auto max-w-5xl px-6 text-center">
        <h2 className="text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
          Acts on its own. Never out of your control.
        </h2>
        <p className="mx-auto mt-4 max-w-2xl text-lg text-fg-secondary">
          Autonomy is graduated, confidence-gated, and reversible by
          construction, bounded at every layer, and one button away from
          stopping entirely.
        </p>

        <div className="mt-12 flex flex-wrap items-center justify-center gap-4">
          {BADGES.map((badge) => (
            <span
              key={badge.label}
              className="inline-flex items-center gap-2 rounded-full border border-line bg-surface-raised/70 px-5 py-2.5 text-sm font-normal text-fg transition-all duration-200 hover:-translate-y-0.5 hover:border-accent/30 hover:bg-surface-raised"
            >
              <badge.icon className="h-4 w-4 text-accent-text" />
              {badge.label}
            </span>
          ))}
        </div>
      </Reveal>
    </section>
  );
}
