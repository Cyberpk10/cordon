import ScreenshotFrame from "@/components/ScreenshotFrame";

const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Cordon%20live%20demo%20request";

export default function Hero({
  hasAnalyzeMalicious,
}: {
  hasAnalyzeMalicious: boolean;
}) {
  return (
    <section className="relative overflow-hidden border-b border-white/5 bg-navy-950">
      <div className="bg-grid pointer-events-none absolute inset-0" aria-hidden />

      <div className="relative mx-auto grid max-w-7xl items-center gap-16 px-6 py-24 lg:grid-cols-2 lg:py-32">
        <div>
          <div className="flex items-center gap-3 text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
            <span className="h-px w-6 bg-brand-blue" />
            AI-Native Defensive Security Platform
          </div>

          <h1 className="mt-6 text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
            Stop phishing the moment it lands.
            <br />
            Prove your controls the moment auditors ask.
          </h1>

          <p className="mt-6 max-w-xl text-lg leading-relaxed text-slate-400">
            Cordon analyzes every email in real time, contains threats
            autonomously within guardrails you control, and turns every
            detection into audit-ready evidence, mapped to MITRE ATT&CK,
            NIST CSF, ISO 27001, and SOC 2.
          </p>

          <div className="mt-10 flex flex-col gap-4 sm:flex-row">
            <a
              href={DEMO_MAILTO}
              className="rounded-md bg-brand-blue px-6 py-3 text-center text-sm font-semibold text-white transition-colors hover:bg-blue-500"
            >
              Get a live demo
            </a>
            <a
              href="#product-tour"
              className="rounded-md border border-white/15 px-6 py-3 text-center text-sm font-semibold text-white transition-colors hover:bg-white/5"
            >
              Take the product tour
            </a>
          </div>
        </div>

        <div className="relative mx-auto w-full max-w-lg lg:justify-self-end">
          <ScreenshotFrame
            src={hasAnalyzeMalicious ? "/screenshots/analyze-malicious.png" : null}
            alt="Cordon's analysis verdict for a malicious phishing email"
            filename="analyze-malicious.png"
            aspectClass="aspect-[4/3]"
            priority
          />
        </div>
      </div>
    </section>
  );
}
