const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Aegis%20design-partner%20demo";

export default function FinalCta() {
  return (
    <section className="bg-white py-24">
      <div className="mx-auto max-w-4xl rounded-3xl bg-gradient-to-br from-navy to-navy-800 px-8 py-16 text-center shadow-xl sm:px-16">
        <span className="inline-flex items-center rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate-200">
          Design-partner program
        </span>
        <h2 className="mt-6 text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Help shape Aegis — get early access
        </h2>
        <p className="mx-auto mt-4 max-w-xl text-lg text-slate-300">
          We&rsquo;re working closely with a small group of security teams to
          refine detection, autonomy, and audit workflows. Join as a design
          partner and shape what ships next.
        </p>
        <a
          href={DEMO_MAILTO}
          className="mt-8 inline-block rounded-full bg-brand-blue px-8 py-3.5 text-sm font-semibold text-white shadow-lg shadow-brand-blue/30 transition-colors hover:bg-blue-500"
        >
          Book a 20-minute demo
        </a>
      </div>
    </section>
  );
}
