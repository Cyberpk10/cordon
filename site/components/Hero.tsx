import HeroPanel from "@/components/HeroPanel";
import HeroCallout from "@/components/HeroCallout";
import Reveal from "@/components/motion/Reveal";

const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Cordon%20live%20demo%20request";

export default function Hero() {
  return (
    <section className="relative overflow-hidden border-b border-white/5 bg-navy-950">
      <div className="bg-grid pointer-events-none absolute inset-0" aria-hidden />

      {/* Ambient depth: two soft, slow-breathing glows, never a full-bleed wash */}
      <div
        className="glow-blob glow-breathe pointer-events-none absolute -top-40 left-1/2 h-[32rem] w-[32rem] -translate-x-1/2 bg-brand-blue/20"
        aria-hidden
      />
      <div
        className="glow-blob glow-breathe pointer-events-none absolute top-20 right-[-6rem] h-72 w-72 bg-brand-purple/10 [animation-delay:3s]"
        aria-hidden
      />

      <div className="relative mx-auto max-w-4xl px-6 pt-24 pb-4 text-center lg:pt-32">
        <Reveal className="flex items-center justify-center gap-3 text-xs font-semibold uppercase tracking-[0.2em] text-slate-500">
          <span className="h-px w-6 bg-brand-blue" />
          AI-Native Defensive Security Platform
        </Reveal>

        <Reveal delay={0.08}>
          <h1 className="mt-6 text-4xl font-bold tracking-tight text-white sm:text-5xl lg:text-6xl">
            Stop phishing the moment it lands.
            <br />
            Prove your controls the moment auditors ask.
          </h1>
        </Reveal>

        <Reveal delay={0.16}>
          <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-slate-400">
            Cordon analyzes every email in real time, contains threats
            autonomously within guardrails you control, and turns every
            detection into audit-ready evidence, mapped to MITRE ATT&CK,
            NIST CSF, ISO 27001, and SOC 2.
          </p>
        </Reveal>

        <Reveal delay={0.24} className="mt-10 flex flex-col items-center justify-center gap-4 sm:flex-row">
          <a
            href={DEMO_MAILTO}
            className="btn-primary rounded-md px-6 py-3 text-center text-sm font-semibold text-white"
          >
            Get a live demo
          </a>
          <a
            href="#product-tour"
            className="btn-secondary rounded-md px-6 py-3 text-center text-sm font-semibold text-white"
          >
            Take the product tour
          </a>
        </Reveal>
      </div>

      <div className="relative mx-auto max-w-7xl px-6 pt-16 pb-24 lg:pb-32">
        <div className="relative mx-auto max-w-3xl">
          <HeroPanel />

          <HeroCallout
            text="Deterministic verdict in under 2 seconds"
            side="left"
            position="left-0 top-[28%] -translate-x-[calc(100%+2rem)]"
            delay={0.9}
          />
          <HeroCallout
            text="Every signal explained, nothing is a black box"
            side="right"
            position="right-0 top-[56%] translate-x-[calc(100%+2rem)]"
            delay={1.05}
          />
          <HeroCallout
            text="Auto mapped to MITRE, NIST, ISO, and SOC 2"
            side="left"
            position="left-0 top-[85%] -translate-x-[calc(100%+2rem)]"
            delay={1.2}
          />
        </div>
      </div>
    </section>
  );
}
