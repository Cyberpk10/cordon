import { Mail, BrainCircuit, Radar, FileCheck2 } from "lucide-react";

const CARDS = [
  {
    icon: Mail,
    title: "Phishing Analysis",
    description:
      "Deterministic and LLM-assisted analysis of headers, links, attachments, and auth results. Malicious verdicts in under 2 seconds.",
  },
  {
    icon: BrainCircuit,
    title: "AI-Attack Detection",
    description:
      "Flags AI-generated and AI-authored social engineering content — the polished, personalized lures other tools miss.",
  },
  {
    icon: Radar,
    title: "Intrusion & Exfiltration",
    description:
      "Behavioral baselines (UEBA) catch impossible travel, brute force, mass access, and data exfiltration — tuned to each user's normal, not a static rule.",
  },
  {
    icon: FileCheck2,
    title: "Compliance Evidence",
    description:
      "Every detection auto-maps to MITRE ATT&CK, NIST CSF 2.0, ISO 27001, and SOC 2 — exportable as a signed audit pack.",
  },
];

export default function PlatformCards() {
  return (
    <section id="platform" className="bg-slate-50 py-24">
      <div className="mx-auto max-w-7xl px-6">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-navy sm:text-4xl">
            One platform, one AI engine
          </h2>
          <p className="mt-4 text-lg text-slate-600">
            Every detection surface shares the same reasoning engine, the
            same evidence trail, and the same guardrails.
          </p>
        </div>

        <div className="mt-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {CARDS.map((card) => (
            <div
              key={card.title}
              className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm transition-shadow hover:shadow-md"
            >
              <div className="inline-flex h-11 w-11 items-center justify-center rounded-xl bg-brand-blue/10">
                <card.icon className="h-5 w-5 text-brand-blue" />
              </div>
              <h3 className="mt-4 text-base font-semibold text-navy">
                {card.title}
              </h3>
              <p className="mt-2 text-sm leading-relaxed text-slate-600">
                {card.description}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
