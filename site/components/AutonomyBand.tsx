import { Layers, Undo2, ShieldOff, Power, ScrollText } from "lucide-react";
import Reveal from "@/components/motion/Reveal";
import SectionHeading from "@/components/ui/SectionHeading";
import FeaturePills from "@/components/ui/FeaturePills";

const BADGES = [
  { icon: Layers, label: "Graduated levels (L0-L3)" },
  { icon: Undo2, label: "Reversible-first actions" },
  { icon: ShieldOff, label: "Executive exclusions" },
  { icon: Power, label: "Kill switch" },
  { icon: ScrollText, label: "Full audit trail" },
];

export default function AutonomyBand() {
  return (
    <section id="autonomy" className="bg-surface-panel section-y">
      <Reveal className="mx-auto max-w-5xl px-6 text-center">
        <SectionHeading
          title={<>Acts on its own. Never out of your control.</>}
          lede={<>Autonomy is graduated, confidence-gated, and reversible by construction, bounded at every layer, and one button away from stopping entirely.</>}
        />

        <FeaturePills items={BADGES} centered />
      </Reveal>
    </section>
  );
}
