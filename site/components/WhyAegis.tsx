import { CheckCircle2 } from "lucide-react";
import Reveal from "@/components/motion/Reveal";
import SectionHeading from "@/components/ui/SectionHeading";

const CHECKLIST = [
  "Real-time phishing verdicts, not just SPF/DKIM checks",
  "Behavioral baselines per user, not static thresholds",
  "Autonomous containment with a hard confidence floor and kill switch",
  "Every action auto-mapped to MITRE, NIST, ISO, and SOC 2",
  "One-click, board-ready and audit-ready evidence packs",
];

export default function WhyAegis() {
  return (
    <section id="why-aegis" className="bg-surface-page section-y">
      <div className="mx-auto grid max-w-7xl items-center gap-16 px-6 lg:grid-cols-2">
        <Reveal>
          <SectionHeading
            title={<>Other tools block. Cordon blocks and proves it.</>}
            align="left"
          />
          <ul className="mt-8 space-y-4">
            {CHECKLIST.map((item) => (
              <li key={item} className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-accent-text" />
                <span className="text-base text-fg-secondary">{item}</span>
              </li>
            ))}
          </ul>
        </Reveal>

        <Reveal
          delay={0.12}
          className="card card-hover p-6 sm:p-8"
        >
          <p className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
            Our principle
          </p>
          <p className="mt-4 text-2xl font-semibold leading-snug text-fg sm:text-3xl">
            Catches phishing like a top analyst. Reports it like an
            auditor.
          </p>
          <div className="mt-8 h-px w-16 bg-accent" />
          <p className="mt-6 text-sm text-fg-secondary">
            Every verdict, every containment action, and every control
            mapping lives in one evidence trail, from the SOC to the
            boardroom.
          </p>
        </Reveal>
      </div>
    </section>
  );
}
