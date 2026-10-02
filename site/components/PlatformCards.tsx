import {
  Mail,
  BrainCircuit,
  Radar,
  FileCheck2,
  Bot,
  Gauge,
  Globe,
} from "lucide-react";

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
      "Flags AI-generated and AI-authored social engineering content (the polished, personalized lures other tools miss).",
  },
  {
    icon: Radar,
    title: "Intrusion & Exfiltration",
    description:
      "Behavioral baselines (UEBA) catch impossible travel, brute force, mass access, and data exfiltration, tuned to each user's normal, not a static rule.",
  },
  {
    icon: FileCheck2,
    title: "Compliance Evidence",
    description:
      "Every detection auto-maps to MITRE ATT&CK, NIST CSF 2.0, ISO 27001, and SOC 2, exportable as a signed audit pack.",
  },
  {
    icon: Bot,
    title: "Analyst Copilot",
    description:
      'Ask questions of your own threat data in plain English. Cordon\'s copilot answers from your cases and events, not the open internet, so "which accounts had failed logins this week" becomes a straight answer.',
  },
  {
    icon: Gauge,
    title: "Continuous Control Monitoring",
    description:
      "Cordon watches whether each compliance control is still producing evidence and flags control drift the moment coverage lapses, so an audit gap surfaces when it happens, not at audit time.",
  },
  {
    icon: Globe,
    title: "Threat Intelligence",
    description:
      "Every sender, link, domain, and IP is checked against known-bad threat-intel feeds. A match against real attacker infrastructure raises the verdict on its own, with the feed and date cited as evidence.",
  },
];

export default function PlatformCards() {
  return (
    <section id="platform" className="bg-navy-950 py-24">
      <div className="mx-auto max-w-7xl px-6">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            One platform, one AI engine
          </h2>
          <p className="mt-4 text-lg text-slate-400">
            Every detection surface shares the same reasoning engine, the
            same evidence trail, and the same guardrails.
          </p>
        </div>

        <div className="mt-16 grid border-t border-white/10 sm:grid-cols-2">
          {CARDS.map((card, i) => (
            <div
              key={card.title}
              className={`flex gap-6 border-b border-white/10 py-10 sm:px-10 ${
                i % 2 === 0 ? "sm:border-r sm:pl-0" : "sm:pl-10"
              }`}
            >
              <div className="flex shrink-0 flex-col items-start gap-4">
                <span className="font-mono text-xs text-slate-600">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <card.icon className="h-5 w-5 text-brand-blue" strokeWidth={1.5} />
              </div>
              <div>
                <h3 className="text-base font-semibold text-white">
                  {card.title}
                </h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">
                  {card.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
