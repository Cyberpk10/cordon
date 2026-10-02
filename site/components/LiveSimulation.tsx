"use client";

import { useState } from "react";
import ScreenshotFrame from "@/components/ScreenshotFrame";

type Tab = "malicious" | "safe";

export default function LiveSimulation({
  hasAnalyzeMalicious,
  hasAnalyzeSafe,
}: {
  hasAnalyzeMalicious: boolean;
  hasAnalyzeSafe: boolean;
}) {
  const [tab, setTab] = useState<Tab>("malicious");

  return (
    <section className="bg-navy-900 py-24">
      <div className="mx-auto max-w-5xl px-6">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            Watch Cordon in action
          </h2>
          <p className="mt-4 text-lg text-slate-400">
            Real analyzer output: a malicious phishing attempt and a clean,
            legitimate email, side by side.
          </p>
        </div>

        <div className="mt-10 flex justify-center gap-2">
          <button
            type="button"
            onClick={() => setTab("malicious")}
            className={`rounded-md px-4 py-2 text-sm font-semibold transition-colors ${
              tab === "malicious"
                ? "bg-brand-blue text-white"
                : "border border-white/10 text-slate-400 hover:text-white"
            }`}
          >
            Malicious email
          </button>
          <button
            type="button"
            onClick={() => setTab("safe")}
            className={`rounded-md px-4 py-2 text-sm font-semibold transition-colors ${
              tab === "safe"
                ? "bg-brand-blue text-white"
                : "border border-white/10 text-slate-400 hover:text-white"
            }`}
          >
            Safe email
          </button>
        </div>

        <div className="mx-auto mt-10 max-w-3xl">
          {tab === "malicious" ? (
            <ScreenshotFrame
              src={hasAnalyzeMalicious ? "/screenshots/analyze-malicious.png" : null}
              alt="Cordon's analysis verdict for a malicious phishing email"
              filename="analyze-malicious.png"
              aspectClass="aspect-[16/10]"
            />
          ) : (
            <ScreenshotFrame
              src={hasAnalyzeSafe ? "/screenshots/analyze-safe.png" : null}
              alt="Cordon's analysis verdict for a legitimate, safe email"
              filename="analyze-safe.png"
              aspectClass="aspect-[16/10]"
            />
          )}
        </div>
      </div>
    </section>
  );
}
