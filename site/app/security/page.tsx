import type { Metadata } from "next";
import {
  Lock,
  Database,
  Users,
  KeyRound,
  ScrollText,
  CheckCircle2,
  Clock,
  Server,
  ShieldAlert,
  BrainCircuit,
} from "lucide-react";
import Nav from "@/components/Nav";
import Footer from "@/components/Footer";
import Reveal from "@/components/motion/Reveal";

export const metadata: Metadata = {
  title: "Security & Trust | Cordon",
  description:
    "How Cordon protects customer data, tests itself, and maps every detection to compliance frameworks. Built by a certified ISO/IEC 27001 Lead Auditor.",
};

const DATA_PROTECTION = [
  {
    icon: Lock,
    title: "Encryption in transit",
    description: "All data moves over TLS/HTTPS.",
  },
  {
    icon: Database,
    title: "Data minimization",
    description:
      "Cordon does not retain the raw content of analyzed email by default. We keep the detection results and evidence needed to serve you, and minimize the rest.",
  },
  {
    icon: Users,
    title: "Strict tenant isolation",
    description:
      "Every record is scoped to your account. One customer can never see another's data, and this is verified by automated security tests.",
  },
  {
    icon: KeyRound,
    title: "Password security",
    description: "Credentials are hashed with Argon2id and never stored in plain text.",
  },
  {
    icon: ScrollText,
    title: "Audit logging",
    description: "Key actions are logged for traceability and audit evidence.",
  },
];

const ACCESS_CONTROLS = [
  "Short-lived access tokens with refresh-token reuse detection.",
  "Least-privilege access to production systems.",
  "Multi-factor authentication on our administrative accounts.",
];

const TESTING = [
  "Over 800 automated tests run before every release, including a dedicated adversarial suite.",
  "A daily red-team program attacks our own detection engine with real-world attacker techniques, scored honestly, including what we miss.",
  "A monthly nation-state / APT “ceiling” test measures our frontier limits.",
];

const AI_HARDENING = [
  "Cordon's AI reasons about the intent behind a message, not just surface patterns, as a bounded signal: it can strengthen a verdict but, by design, can never override the deterministic rules or turn a malicious email into a safe one.",
  "We hardened this AI layer against prompt injection, where an attacker hides instructions inside an email to fool the analyzer. The email is always treated as untrusted data, never as instructions.",
  "We test it directly: when fed a message instructing the AI to mark itself safe, it refused, and flagged the manipulation attempt itself as a sign of malicious intent.",
];

const SUB_PROCESSORS = [
  { name: "Anthropic", purpose: "AI analysis" },
  { name: "Render", purpose: "hosting and database" },
  { name: "Vercel", purpose: "web hosting" },
  { name: "Mailgun", purpose: "authorized email" },
  { name: "Cloudflare", purpose: "network protection" },
];

const PRIVACY_MAILTO = "mailto:paakowansah@icloud.com?subject=Cordon%20privacy%20inquiry";
const SECURITY_MAILTO =
  "mailto:security@cordoncybersec.us?subject=Security%20disclosure";

export default function SecurityPage() {
  return (
    <>
      <Nav />
      <main className="flex-1">
        <section className="relative overflow-hidden border-b border-white/5 bg-navy-950">
          <div
            className="glow-blob glow-breathe pointer-events-none absolute -top-32 left-1/2 h-96 w-96 -translate-x-1/2 bg-brand-blue/15"
            aria-hidden
          />
          <Reveal className="relative mx-auto max-w-3xl px-6 py-24 text-center">
            <h1 className="text-4xl font-bold tracking-tight text-white sm:text-5xl">
              Security &amp; Trust
            </h1>
            <p className="mx-auto mt-6 max-w-2xl text-lg leading-relaxed text-slate-400">
              Cordon is built by a certified ISO/IEC 27001 Lead Auditor, so security and
              compliance are not afterthoughts. They are the product. Here is how we protect
              your data and hold ourselves accountable.
            </p>
          </Reveal>
        </section>

        <section className="bg-navy-950 py-24">
          <div className="mx-auto max-w-7xl px-6">
            <Reveal>
              <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
                How we protect your data
              </h2>
            </Reveal>

            <div className="mt-12 grid border-t border-white/10 sm:grid-cols-2">
              {DATA_PROTECTION.map((item, i) => (
                <Reveal key={item.title} delay={Math.min(i * 0.05, 0.2)} y={14}>
                  <div
                    className={`flex h-full gap-6 border-b border-white/10 py-10 transition-colors duration-300 hover:bg-white/[0.02] sm:px-10 ${
                      i % 2 === 0 ? "sm:border-r sm:pl-0" : "sm:pl-10"
                    }`}
                  >
                    <item.icon
                      className="h-5 w-5 shrink-0 text-brand-blue"
                      strokeWidth={1.5}
                    />
                    <div>
                      <h3 className="text-base font-semibold text-white">{item.title}</h3>
                      <p className="mt-2 text-sm leading-relaxed text-slate-400">
                        {item.description}
                      </p>
                    </div>
                  </div>
                </Reveal>
              ))}
            </div>
          </div>
        </section>

        <section className="border-y border-white/5 bg-navy-900 py-24">
          <Reveal className="mx-auto max-w-4xl px-6">
            <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Authentication and access
            </h2>
            <ul className="mt-8 space-y-4">
              {ACCESS_CONTROLS.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" />
                  <span className="text-base text-slate-300">{item}</span>
                </li>
              ))}
            </ul>
          </Reveal>
        </section>

        <section className="bg-navy-950 py-24">
          <Reveal className="mx-auto max-w-4xl px-6">
            <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              How we test ourselves
            </h2>
            <ul className="mt-8 space-y-4">
              {TESTING.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" />
                  <span className="text-base text-slate-300">{item}</span>
                </li>
              ))}
            </ul>
            <p className="mt-8 border-t border-white/10 pt-8 text-base leading-relaxed text-slate-400">
              We publish what we catch and what we miss, because a security vendor that hides
              its blind spots is a security risk.
            </p>
          </Reveal>
        </section>

        <section className="bg-navy-950 py-24">
          <Reveal className="mx-auto max-w-4xl px-6">
            <div className="flex items-center gap-3">
              <BrainCircuit className="h-5 w-5 text-brand-blue" strokeWidth={1.5} />
              <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
                AI hardened against manipulation
              </h2>
            </div>
            <ul className="mt-8 space-y-4">
              {AI_HARDENING.map((item) => (
                <li key={item} className="flex items-start gap-3">
                  <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" />
                  <span className="text-base text-slate-300">{item}</span>
                </li>
              ))}
            </ul>
          </Reveal>
        </section>

        <section className="border-y border-white/5 bg-navy-900 py-24">
          <Reveal className="mx-auto max-w-4xl px-6">
            <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
              Compliance
            </h2>

            <div className="mt-8 space-y-4">
              <div className="flex items-start gap-3 rounded-2xl border border-white/10 bg-navy-950 p-6 transition-colors duration-300 hover:border-white/15">
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-brand-blue" />
                <p className="text-base text-slate-300">
                  Every detection auto-maps to ISO 27001, NIST CSF 2.0, SOC 2, and MITRE
                  ATT&amp;CK, and is exportable as audit evidence.
                </p>
              </div>

              <div className="flex items-start gap-3 rounded-2xl border border-white/10 bg-navy-950 p-6 transition-colors duration-300 hover:border-white/15">
                <Clock className="mt-0.5 h-5 w-5 shrink-0 text-slate-500" />
                <div>
                  <span className="inline-flex items-center rounded-full border border-white/15 bg-white/5 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-slate-300">
                    On our roadmap
                  </span>
                  <p className="mt-3 text-base text-slate-300">
                    SOC 2 Type II is on our near-term roadmap, as is an independent
                    third-party penetration test. We will update this page as each is
                    completed.
                  </p>
                </div>
              </div>
            </div>
          </Reveal>
        </section>

        <section className="bg-navy-950 py-24">
          <Reveal className="mx-auto max-w-4xl px-6">
            <div className="rounded-2xl border border-white/10 bg-navy-900 p-10 transition-all duration-300 hover:border-white/15 hover:shadow-xl hover:shadow-black/30">
              <div className="flex items-center gap-3">
                <Server className="h-5 w-5 text-brand-blue" strokeWidth={1.5} />
                <h2 className="text-2xl font-bold tracking-tight text-white">
                  Sub-processors
                </h2>
              </div>
              <p className="mt-6 text-base leading-relaxed text-slate-400">
                We rely on a small set of vetted providers:{" "}
                {SUB_PROCESSORS.map((p, i) => (
                  <span key={p.name}>
                    {p.name} ({p.purpose})
                    {i < SUB_PROCESSORS.length - 2
                      ? ", "
                      : i === SUB_PROCESSORS.length - 2
                        ? ", and "
                        : ""}
                  </span>
                ))}
                . A current list is available on request. See our{" "}
                <a
                  href={PRIVACY_MAILTO}
                  className="font-medium text-brand-blue hover:underline"
                >
                  Privacy Policy
                </a>{" "}
                for more detail.
              </p>
            </div>
          </Reveal>
        </section>

        <section className="border-t border-white/5 bg-navy-900 py-24">
          <Reveal className="mx-auto max-w-4xl px-6">
            <div className="rounded-2xl border border-white/10 bg-navy-950 p-10 transition-all duration-300 hover:border-white/15 hover:shadow-xl hover:shadow-black/30">
              <div className="flex items-center gap-3">
                <ShieldAlert className="h-5 w-5 text-brand-blue" strokeWidth={1.5} />
                <h2 className="text-2xl font-bold tracking-tight text-white">
                  Responsible disclosure
                </h2>
              </div>
              <p className="mt-6 text-base leading-relaxed text-slate-400">
                Found a security issue? We want to hear from you. Email{" "}
                <a
                  href={SECURITY_MAILTO}
                  className="font-medium text-brand-blue hover:underline"
                >
                  security@cordoncybersec.us
                </a>{" "}
                and we will respond promptly. Please give us a reasonable chance to
                remediate before public disclosure.
              </p>
            </div>
          </Reveal>
        </section>

        <div className="bg-navy-950 pb-16">
          <div className="mx-auto max-w-4xl px-6 text-center">
            <p className="text-sm text-slate-500">
              Cordon is in early access. This page reflects our current posture and will be
              kept current as it evolves.
            </p>
          </div>
        </div>
      </main>
      <Footer />
    </>
  );
}
