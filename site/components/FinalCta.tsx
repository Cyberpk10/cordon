import Reveal from "@/components/motion/Reveal";

const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Cordon%20design-partner%20demo";

export default function FinalCta() {
  return (
    <section id="design-partner" className="relative overflow-hidden bg-navy-950 py-24">
      <Reveal
        y={24}
        className="relative mx-auto max-w-4xl overflow-hidden rounded-2xl border border-white/10 bg-gradient-to-br from-navy to-navy-800 px-8 py-16 text-center sm:px-16"
      >
        <div
          className="glow-blob glow-breathe pointer-events-none absolute -bottom-24 left-1/2 h-72 w-72 -translate-x-1/2 bg-brand-blue/25"
          aria-hidden
        />
        <div className="relative">
          <span className="inline-flex items-center rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200">
            Design-partner program
          </span>
          <h2 className="mt-6 text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Help shape Cordon: get early access
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-lg text-slate-300">
            We&rsquo;re working closely with a small group of security teams to
            refine detection, autonomy, and audit workflows. Join as a design
            partner and shape what ships next.
          </p>
          <a
            href={DEMO_MAILTO}
            className="btn-primary mt-8 inline-block rounded-md px-8 py-3.5 text-sm font-semibold text-white"
          >
            Book a 20-minute demo
          </a>
        </div>
      </Reveal>
    </section>
  );
}
