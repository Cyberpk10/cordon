import { Activity, Link2, TriangleAlert, Clock } from "lucide-react";
import Reveal from "@/components/motion/Reveal";
import SectionHeading from "@/components/ui/SectionHeading";
import FeaturePills from "@/components/ui/FeaturePills";

const POINTS = [
  { icon: Activity, label: "Live per-account threat level" },
  { icon: Link2, label: "Kill-chain-aware signal correlation" },
  { icon: TriangleAlert, label: "“Attack Forming” alerts with the full timeline" },
  { icon: Clock, label: "Days of lead time, verified in testing" },
];

export default function EarlyWarning() {
  return (
    <section id="early-warning" className="bg-surface-panel section-y">
      <Reveal className="mx-auto max-w-4xl px-6">
        <SectionHeading
          title={<>See the attack forming, not just the aftermath.</>}
          lede={<>Cordon keeps a live threat level for every account that rises as early signals accumulate: a phishing click, an unusual login, a first-time reach into sensitive files. When enough of them line up in the wrong order, it raises an &ldquo;Attack Forming&rdquo; alert with the full signal timeline, before it becomes a full incident. In our own testing it fired mid-chain with days of lead time before the data theft. For attacks that leave a trail in email and activity, that is the difference between responding to a breach and stopping one.</>}
          align="left"
        />

        <FeaturePills items={POINTS} />
      </Reveal>
    </section>
  );
}
