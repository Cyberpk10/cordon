import Reveal from "@/components/motion/Reveal";

const STATS = [
  { value: "<2s", label: "to a verdict", sub: "from upload to verdict" },
  {
    value: "4",
    label: "frameworks mapped",
    sub: "MITRE, NIST, ISO, SOC 2",
  },
  {
    value: "1-click",
    label: "audit packs",
    sub: "board- and auditor-ready",
  },
  {
    value: "L0-L3",
    label: "autonomy",
    sub: "graduated, reversible-first control",
  },
];

export default function StatStrip() {
  return (
    <section className="border-y border-line/60 bg-surface-panel">
      <Reveal
        y={14}
        className="mx-auto grid max-w-7xl grid-cols-2 gap-8 px-6 py-12 sm:grid-cols-4"
      >
        {STATS.map((stat) => (
          <div key={stat.label} className="text-center sm:text-left">
            <div className="font-display text-3xl font-semibold tracking-tight text-fg">
              {stat.value}
            </div>
            <div className="mt-1 text-sm font-semibold text-fg-secondary">
              {stat.label}
            </div>
            <div className="mt-0.5 text-xs text-fg-muted">{stat.sub}</div>
          </div>
        ))}
      </Reveal>
    </section>
  );
}
