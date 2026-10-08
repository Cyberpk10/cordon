import { ShieldCheck, UserCheck, GraduationCap, Lock } from "lucide-react";
import Reveal from "@/components/motion/Reveal";

const POINTS = [
  { icon: ShieldCheck, label: "Safe, authorized simulations" },
  { icon: UserCheck, label: "Per-person human risk scoring" },
  { icon: GraduationCap, label: "Targeted micro-training on the exact lure" },
  {
    icon: Lock,
    label: "No credential capture, verified-domain and admin gated",
  },
];

export default function PhishingSimulation() {
  return (
    <section id="simulation" className="bg-navy-950 py-24">
      <Reveal className="mx-auto max-w-4xl px-6">
        <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          Catch the phish, and train the people it targets.
        </h2>
        <p className="mt-6 text-lg leading-relaxed text-slate-400">
          Cordon runs safe, authorized phishing simulations against your own
          staff, then scores each person&rsquo;s human risk from how they
          respond. Anyone who clicks gets targeted micro-training tied to
          the exact lure they fell for. It is gated by design: verified
          domains only, admin authorization required, and no real
          credential is ever captured or stored. Detection protects the
          inbox. This makes your people harder to fool in the first place.
        </p>

        <div className="mt-10 flex flex-wrap gap-3">
          {POINTS.map((point) => (
            <span
              key={point.label}
              className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-5 py-2.5 text-sm font-medium text-slate-200 transition-all duration-200 hover:-translate-y-0.5 hover:border-brand-blue/30 hover:bg-white/[0.08]"
            >
              <point.icon className="h-4 w-4 text-brand-blue" />
              {point.label}
            </span>
          ))}
        </div>
      </Reveal>
    </section>
  );
}
