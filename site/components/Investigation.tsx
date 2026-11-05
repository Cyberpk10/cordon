import { SearchCheck, History, ListChecks, FileOutput } from "lucide-react";
import Reveal from "@/components/motion/Reveal";
import SectionHeading from "@/components/ui/SectionHeading";
import FeaturePills from "@/components/ui/FeaturePills";

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
    <section id="investigation" className="bg-surface-panel section-y">
      <Reveal className="mx-auto max-w-4xl px-6">
        <SectionHeading
          title={<>From flagged to fully investigated, in one step.</>}
          lede={<>When Cordon flags an email threat, it does not stop at a verdict. An investigation agent automatically gathers the context: the sender&rsquo;s history, related activity on the affected account, threat-intelligence matches, and the kill-chain timeline. It assembles a timeline and a scope assessment, writes a clear investigation that cites the exact evidence behind every finding, and recommends the response for you to approve. The finished investigation exports straight into your audit evidence, so the work that protects you also proves it.</>}
          align="left"
        />

        <FeaturePills items={POINTS} />
      </Reveal>
    </section>
  );
}
