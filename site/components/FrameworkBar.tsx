import Reveal from "@/components/motion/Reveal";

const FRAMEWORKS = ["ISO 27001", "NIST CSF", "SOC 2", "MITRE ATT&CK"];

export default function FrameworkBar() {
  return (
    <section className="border-y border-white/5 bg-navy-900">
      <Reveal
        y={12}
        className="mx-auto flex max-w-7xl flex-col items-center gap-5 px-6 py-8 sm:flex-row sm:justify-between"
      >
        <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Every detection maps to
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          {FRAMEWORKS.map((framework) => (
            <span
              key={framework}
              className="rounded-md border border-white/10 px-3.5 py-1.5 text-sm font-medium text-slate-300 transition-colors duration-200 hover:border-brand-blue/40 hover:text-white"
            >
              {framework}
            </span>
          ))}
        </div>
      </Reveal>
    </section>
  );
}
