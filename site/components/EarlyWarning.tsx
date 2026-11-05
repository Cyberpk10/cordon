import { Activity, Link2, TriangleAlert, Clock } from "lucide-react";
import Reveal from "@/components/motion/Reveal";

const POINTS = [
  { icon: Activity, label: "Live per-account threat level" },
  { icon: Link2, label: "Kill-chain-aware signal correlation" },
  { icon: TriangleAlert, label: "“Attack Forming” alerts with the full timeline" },
  { icon: Clock, label: "Days of lead time, verified in testing" },
];

export default function EarlyWarning() {
  return (
    <section id="early-warning" className="bg-surface-panel py-24">
      <Reveal className="mx-auto max-w-4xl px-6">
        <h2 className="text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
          See the attack forming, not just the aftermath.
        </h2>
        <p className="mt-6 text-lg leading-relaxed text-fg-secondary">
          Cordon keeps a live threat level for every account that rises as
          early signals accumulate: a phishing click, an unusual login, a
          first-time reach into sensitive files. When enough of them line up
          in the wrong order, it raises an &ldquo;Attack Forming&rdquo;
          alert with the full signal timeline, before it becomes a full
          incident. In our own testing it fired mid-chain with days of lead
          time before the data theft. For attacks that leave a trail in
          email and activity, that is the difference between responding to
          a breach and stopping one.
        </p>

        <div className="mt-10 flex flex-wrap gap-3">
          {POINTS.map((point) => (
            <span
              key={point.label}
              className="inline-flex items-center gap-2 rounded-full border border-line bg-surface-raised/70 px-5 py-2.5 text-sm font-normal text-fg transition-all duration-200 hover:-translate-y-0.5 hover:border-accent/30 hover:bg-surface-raised"
            >
              <point.icon className="h-4 w-4 text-accent-text" />
              {point.label}
            </span>
          ))}
        </div>
      </Reveal>
    </section>
  );
}
