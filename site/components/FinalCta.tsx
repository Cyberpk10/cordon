import Reveal from "@/components/motion/Reveal";

const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Cordon%20design-partner%20demo";

export default function FinalCta() {
  return (
    <section id="design-partner" className="relative overflow-hidden bg-surface-page py-24">
      <Reveal
        y={24}
        className="relative mx-auto max-w-4xl overflow-hidden rounded-card border border-line bg-gradient-to-br from-surface-panel to-surface-raised px-8 py-16 text-center sm:px-16"
      >
        <div
          className="glow-blob glow-breathe pointer-events-none absolute -bottom-24 left-1/2 h-72 w-72 -translate-x-1/2 bg-accent/25"
          aria-hidden
        />
        <div className="relative">
          <span className="inline-flex items-center rounded-full border border-line-strong bg-surface-raised/70 px-4 py-1.5 text-xs font-semibold uppercase tracking-wide text-fg">
            Design-partner program
          </span>
          <h2 className="mt-6 text-3xl font-semibold tracking-tight text-fg sm:text-4xl">
            Help shape Cordon: get early access
          </h2>
          <p className="mx-auto mt-4 max-w-xl text-lg text-fg-secondary">
            We&rsquo;re working closely with a small group of security teams to
            refine detection, autonomy, and audit workflows. Join as a design
            partner and shape what ships next.
          </p>
          <a
            href={DEMO_MAILTO}
            className="btn-primary mt-8 inline-block rounded-control px-8 py-3.5 text-sm font-semibold text-white"
          >
            Book a 20-minute demo
          </a>
        </div>
      </Reveal>
    </section>
  );
}
