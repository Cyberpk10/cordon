import { CheckCircle2 } from "lucide-react";

const CHECKLIST = [
  "Real-time phishing verdicts, not just SPF/DKIM checks",
  "Behavioral baselines per user, not static thresholds",
  "Autonomous containment with a hard confidence floor and kill switch",
  "Every action auto-mapped to MITRE, NIST, ISO, and SOC 2",
  "One-click, board-ready and audit-ready evidence packs",
];

export default function WhyAegis() {
  return (
    <section id="why-aegis" className="bg-slate-50 py-24">
      <div className="mx-auto grid max-w-7xl items-center gap-16 px-6 lg:grid-cols-2">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-navy sm:text-4xl">
            Other tools block. Aegis blocks and proves it.
          </h2>
          <ul className="mt-8 space-y-4">
            {CHECKLIST.map((item) => (
              <li key={item} className="flex items-start gap-3">
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" />
                <span className="text-base text-slate-700">{item}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="rounded-3xl border border-brand-blue/20 bg-gradient-to-br from-navy to-navy-800 p-10 shadow-xl">
          <p className="text-2xl font-semibold leading-snug text-white sm:text-3xl">
            &ldquo;Catches phishing like a top analyst. Reports it like an
            auditor.&rdquo;
          </p>
          <div className="mt-8 h-px w-16 bg-brand-blue" />
          <p className="mt-6 text-sm text-slate-300">
            Every verdict, every containment action, and every control
            mapping lives in one evidence trail — from the SOC to the
            boardroom.
          </p>
        </div>
      </div>
    </section>
  );
}
