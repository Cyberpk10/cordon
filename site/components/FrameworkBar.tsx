import Reveal from "@/components/motion/Reveal";

const FRAMEWORKS = ["ISO 27001", "NIST CSF", "SOC 2", "MITRE ATT&CK"];

export default function FrameworkBar() {
  return (
    <section className="bg-surface-panel">
      <Reveal
        y={12}
        className="mx-auto flex max-w-7xl flex-col items-center gap-5 px-6 py-8 sm:flex-row sm:justify-between"
      >
        <p className="text-xs font-semibold uppercase tracking-wider text-fg-muted">
          Every detection maps to
        </p>
        <div className="flex flex-wrap items-center justify-center gap-3">
          {FRAMEWORKS.map((framework) => (
            <span
              key={framework}
              className="rounded-control border border-line px-3.5 py-1.5 text-sm font-normal text-fg-secondary"
            >
              {framework}
            </span>
          ))}
        </div>
      </Reveal>
    </section>
  );
}
