import { ShieldCheck, UserCheck, GraduationCap, Lock } from "lucide-react";
import Reveal from "@/components/motion/Reveal";
import SectionHeading from "@/components/ui/SectionHeading";
import FeaturePills from "@/components/ui/FeaturePills";

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
    <section id="simulation" className="bg-surface-page section-y">
      <Reveal className="mx-auto max-w-4xl px-6">
        <SectionHeading
          title={<>Catch the phish, and train the people it targets.</>}
          lede={<>Cordon runs safe, authorized phishing simulations against your own staff, then scores each person&rsquo;s human risk from how they respond. Anyone who clicks gets targeted micro-training tied to the exact lure they fell for. It is gated by design: verified domains only, admin authorization required, and no real credential is ever captured or stored. Detection protects the inbox. This makes your people harder to fool in the first place.</>}
          align="left"
        />

        <FeaturePills items={POINTS} />
      </Reveal>
    </section>
  );
}
