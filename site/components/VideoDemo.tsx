import { Film } from "lucide-react";
import Reveal from "@/components/motion/Reveal";

export default function VideoDemo({
  hasWalkthroughVideo,
}: {
  hasWalkthroughVideo: boolean;
}) {
  return (
    <section className="bg-navy-950 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <Reveal className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Watch the full Cordon walkthrough
          </h2>
          <p className="mt-4 text-lg text-slate-400">
            A 90-second walkthrough: detection, early warning, staff
            training, and audit-ready compliance.
          </p>
        </Reveal>

        <Reveal
          delay={0.1}
          y={28}
          className="mx-auto mt-14 max-w-[900px] overflow-hidden rounded-xl border border-white/10 shadow-2xl shadow-black/40 transition-shadow duration-300 hover:shadow-brand-blue/10"
        >
          {hasWalkthroughVideo ? (
            <video className="w-full" controls preload="metadata">
              <source
                src="/video/cordon-walkthrough-90s.mp4"
                type="video/mp4"
              />
              Your browser doesn&apos;t support embedded video. You can{" "}
              <a
                href="/video/cordon-walkthrough-90s.mp4"
                className="text-brand-blue underline"
              >
                download the demo
              </a>{" "}
              instead.
            </video>
          ) : (
            <div className="flex aspect-video w-full flex-col items-center justify-center gap-3 border-2 border-dashed border-white/10 bg-navy-900 px-6 text-center">
              <Film className="h-6 w-6 text-slate-600" />
              <p className="text-sm font-medium text-slate-400">
                90-second product walkthrough
              </p>
              <p className="font-mono text-xs text-slate-600">
                public/video/cordon-walkthrough-90s.mp4
              </p>
            </div>
          )}
        </Reveal>
      </div>
    </section>
  );
}
