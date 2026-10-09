import { SearchCheck, History, ListChecks, FileOutput } from "lucide-react";
import Reveal from "@/components/motion/Reveal";

const POINTS = [
  {
    icon: SearchCheck,
    label: "Grounded by design: every finding cites real evidence, so it cannot invent conclusions",
  },
  { icon: History, label: "Automatic timeline and blast-radius assessment" },
  {
    icon: ListChecks,
    label: "Recommended response, with you in control (nothing acts on its own)",
  },
  { icon: FileOutput, label: "Exports as audit-ready evidence" },
];

export default function Investigation() {
  return (
    <section id="investigation" className="border-t border-white/5 bg-navy-900 py-24">
      <Reveal className="mx-auto max-w-4xl px-6">
        <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
          From flagged to fully investigated, in one step.
        </h2>
        <p className="mt-6 text-lg leading-relaxed text-slate-400">
          When Cordon flags an email threat, it does not stop at a verdict. An
          investigation agent automatically gathers the context: the
          sender&rsquo;s history, related activity on the affected account,
          threat-intelligence matches, and the kill-chain timeline. It
          assembles a timeline and a scope assessment, writes a clear
          investigation that cites the exact evidence behind every finding,
          and recommends the response for you to approve. The finished
          investigation exports straight into your audit evidence, so the
          work that protects you also proves it.
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
