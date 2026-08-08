import { Sparkles, TriangleAlert } from "lucide-react";

const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Aegis%20live%20demo%20request";

export default function Hero() {
  return (
    <section className="relative overflow-hidden bg-gradient-to-b from-navy via-navy to-navy-950">
      <div
        className="pointer-events-none absolute -top-40 right-0 h-[32rem] w-[32rem] rounded-full bg-brand-blue/30 blur-3xl"
        aria-hidden
      />
      <div
        className="pointer-events-none absolute -bottom-32 left-0 h-[28rem] w-[28rem] rounded-full bg-brand-purple/20 blur-3xl"
        aria-hidden
      />

      <div className="relative mx-auto grid max-w-7xl items-center gap-16 px-6 py-24 lg:grid-cols-2 lg:py-32">
        <div>
          <span className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200">
            <Sparkles className="h-3.5 w-3.5 text-brand-purple" />
            AI-Native Defensive Security Platform
          </span>

          <h1 className="mt-6 text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
            Stop phishing the moment it lands.
            <br />
            Prove your controls the moment auditors ask.
          </h1>

          <p className="mt-6 max-w-xl text-lg leading-relaxed text-slate-300">
            Aegis analyzes every email in real time, contains threats
            autonomously within guardrails you control, and turns every
            detection into audit-ready evidence — mapped to MITRE ATT&CK,
            NIST CSF, ISO 27001, and SOC 2.
          </p>

          <div className="mt-10 flex flex-col gap-4 sm:flex-row">
            <a
              href={DEMO_MAILTO}
              className="rounded-full bg-brand-blue px-6 py-3 text-center text-sm font-semibold text-white shadow-lg shadow-brand-blue/30 transition-colors hover:bg-blue-500"
            >
              Get a live demo
            </a>
            <a
              href="#product-tour"
              className="rounded-full border border-white/20 px-6 py-3 text-center text-sm font-semibold text-white transition-colors hover:bg-white/10"
            >
              Take the product tour
            </a>
          </div>
        </div>

        <div className="relative mx-auto w-full max-w-md lg:justify-self-end">
          <div className="rounded-2xl border border-white/10 bg-navy-800/80 p-6 shadow-2xl shadow-black/40 backdrop-blur">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
                Case #4471
              </span>
              <span className="inline-flex items-center gap-1.5 rounded-full bg-red-500/15 px-3 py-1 text-xs font-bold uppercase tracking-wide text-red-400">
                <TriangleAlert className="h-3.5 w-3.5" />
                Malicious
              </span>
            </div>

            <div className="mt-4 flex items-baseline gap-2">
              <span className="text-4xl font-bold text-white">92</span>
              <span className="text-sm text-slate-400">/ 100 risk score</span>
            </div>

            <div className="mt-4 space-y-1 text-sm">
              <p className="text-slate-400">
                From:{" "}
                <span className="text-slate-200">
                  billing-support@paypaI-secure.com
                </span>
              </p>
              <p className="text-slate-400">
                Subject:{" "}
                <span className="text-slate-200">
                  Urgent: verify your account within 24 hours
                </span>
              </p>
            </div>

            <div className="mt-4 rounded-lg border border-white/10 bg-white/5 p-3 text-xs leading-relaxed text-slate-300">
              <span className="font-semibold text-brand-blue">
                AI analyst:
              </span>{" "}
              Lookalike domain, urgency language, and a credential-harvesting
              link converge on a single verdict — quarantine recommended.
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
