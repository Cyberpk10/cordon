"use client";

import { useEffect, useState } from "react";
import Image from "next/image";
import { CheckCircle2, TriangleAlert, ShieldCheck, RotateCcw } from "lucide-react";

type Finding = {
  label: string;
  ok?: boolean;
};

const FINDINGS: Finding[] = [
  { label: "Parsing headers & authentication", ok: true },
  { label: "SPF/DKIM/DMARC all failed" },
  { label: "Look-alike domain: micros0ft-verify.com" },
  { label: "Urgency & pressure language" },
  { label: "Credential-harvesting request" },
  { label: "Likely AI-generated text" },
];

const CONTROL_CHIPS = [
  { framework: "MITRE", id: "T1566", className: "bg-slate-100 text-slate-700" },
  { framework: "NIST", id: "DE.CM-04", className: "bg-blue-100 text-blue-700" },
  { framework: "SOC2", id: "CC7.2", className: "bg-emerald-100 text-emerald-700" },
  { framework: "ISO", id: "A.5.14", className: "bg-purple-100 text-purple-700" },
];

const RISK_SCORE = 92;
const FINDING_START = 600;
const FINDING_INTERVAL = 500;
const GAUGE_START = FINDING_START + FINDINGS.length * FINDING_INTERVAL + 400;
const GAUGE_DURATION = 1200;
const VERDICT_START = GAUGE_START + GAUGE_DURATION;
const CHIP_START = VERDICT_START + 300;
const CHIP_INTERVAL = 250;
const BANNER_START = CHIP_START + CONTROL_CHIPS.length * CHIP_INTERVAL + 300;

function RiskGauge({ value }: { value: number }) {
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference * (1 - value / 100);

  return (
    <div className="relative h-20 w-20 shrink-0">
      <svg viewBox="0 0 72 72" className="h-20 w-20 -rotate-90">
        <circle cx="36" cy="36" r={radius} fill="none" stroke="#e2e8f0" strokeWidth="6" />
        <circle
          cx="36"
          cy="36"
          r={radius}
          fill="none"
          stroke="url(#gaugeGrad)"
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          className="transition-[stroke-dashoffset] duration-100 ease-linear"
        />
        <defs>
          <linearGradient id="gaugeGrad" x1="0" y1="0" x2="1" y2="1">
            <stop offset="0" stopColor="#2f6bff" />
            <stop offset="1" stopColor="#8b5cf6" />
          </linearGradient>
        </defs>
      </svg>
      <div className="absolute inset-0 flex items-center justify-center text-base font-bold text-navy">
        {value}
      </div>
    </div>
  );
}

function SimulationCard() {
  const [scanning, setScanning] = useState(true);
  const [visibleFindings, setVisibleFindings] = useState(0);
  const [gaugeValue, setGaugeValue] = useState(0);
  const [verdictVisible, setVerdictVisible] = useState(false);
  const [visibleChips, setVisibleChips] = useState(0);
  const [bannerVisible, setBannerVisible] = useState(false);
  const [status, setStatus] = useState<"analyzing" | "contained">("analyzing");

  useEffect(() => {
    const timeouts: ReturnType<typeof setTimeout>[] = [];
    const intervals: ReturnType<typeof setInterval>[] = [];

    FINDINGS.forEach((_, i) => {
      timeouts.push(
        setTimeout(
          () => setVisibleFindings((n) => Math.max(n, i + 1)),
          FINDING_START + i * FINDING_INTERVAL
        )
      );
    });

    timeouts.push(setTimeout(() => setScanning(false), GAUGE_START));

    timeouts.push(
      setTimeout(() => {
        const steps = 30;
        const stepDuration = GAUGE_DURATION / steps;
        let step = 0;
        const gaugeInterval = setInterval(() => {
          step += 1;
          setGaugeValue(Math.min(RISK_SCORE, Math.round((RISK_SCORE * step) / steps)));
          if (step >= steps) clearInterval(gaugeInterval);
        }, stepDuration);
        intervals.push(gaugeInterval);
      }, GAUGE_START)
    );

    timeouts.push(setTimeout(() => setVerdictVisible(true), VERDICT_START));

    CONTROL_CHIPS.forEach((_, i) => {
      timeouts.push(
        setTimeout(
          () => setVisibleChips((n) => Math.max(n, i + 1)),
          CHIP_START + i * CHIP_INTERVAL
        )
      );
    });

    timeouts.push(
      setTimeout(() => {
        setBannerVisible(true);
        setStatus("contained");
      }, BANNER_START)
    );

    return () => {
      timeouts.forEach(clearTimeout);
      intervals.forEach(clearInterval);
    };
  }, []);

  return (
    <div className="mt-14 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl">
          <div className="flex flex-wrap items-center justify-between gap-2 bg-navy px-5 py-3">
            <div className="flex items-center gap-2 text-white">
              <Image
                src="/brand/aegis-icon.svg"
                alt="Aegis"
                width={24}
                height={24}
                className="h-5 w-5"
              />
              <span className="text-sm font-bold tracking-tight">AEGIS</span>
            </div>
            <span
              className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold transition-colors ${
                status === "analyzing"
                  ? "bg-blue-500/20 text-blue-300"
                  : "bg-emerald-500/20 text-emerald-300"
              }`}
            >
              {status === "analyzing" ? (
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-blue-300" />
              ) : (
                <CheckCircle2 className="h-3.5 w-3.5" />
              )}
              {status === "analyzing" ? "Analyzing…" : "Contained"}
            </span>
          </div>

          <div className="grid gap-6 p-6 sm:p-8 lg:grid-cols-2">
            <div className="relative overflow-hidden rounded-xl border border-slate-200 bg-white">
              <div className="border-b border-slate-100 bg-slate-50 px-4 py-3 text-xs">
                <div>
                  <span className="font-medium text-slate-500">From: </span>
                  <span className="text-slate-800">
                    it-support@micros0ft-verify.com
                  </span>
                </div>
                <div className="mt-1">
                  <span className="font-medium text-slate-500">Subject: </span>
                  <span className="font-semibold text-slate-900">
                    Urgent: verify your password within 24 hours
                  </span>
                </div>
              </div>
              <div className="px-4 py-4 text-sm leading-relaxed text-slate-700">
                <p>Dear user,</p>
                <p className="mt-2">
                  We detected unusual sign-in activity on your account. To
                  avoid suspension, verify your password immediately at{" "}
                  <span className="font-medium text-blue-600 underline">
                    micros0ft-verify.com/login
                  </span>
                  .
                </p>
                <p className="mt-2">
                  Failure to act within 24 hours will result in permanent
                  account lockout.
                </p>
                <p className="mt-4">— IT Support Team</p>
              </div>

              {scanning && (
                <div
                  className="pointer-events-none absolute inset-x-0 h-12 bg-gradient-to-b from-transparent via-brand-blue/25 to-transparent"
                  style={{ animation: "scan-sweep 1.8s ease-in-out infinite" }}
                />
              )}
            </div>

            <div className="flex flex-col gap-5">
              <ul className="space-y-2.5">
                {FINDINGS.map((f, i) => (
                  <li
                    key={f.label}
                    className={`flex items-center gap-2.5 text-sm transition-opacity duration-500 ${
                      i < visibleFindings ? "opacity-100" : "opacity-0"
                    }`}
                  >
                    {f.ok ? (
                      <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                    ) : (
                      <TriangleAlert className="h-4 w-4 shrink-0 text-red-500" />
                    )}
                    <span
                      className={
                        f.ok ? "text-slate-600" : "font-medium text-slate-800"
                      }
                    >
                      {f.label}
                    </span>
                  </li>
                ))}
              </ul>

              <div className="flex items-center gap-5 border-t border-slate-100 pt-5">
                <RiskGauge value={gaugeValue} />
                <div
                  className={`transition-opacity duration-500 ${
                    verdictVisible ? "opacity-100" : "opacity-0"
                  }`}
                >
                  <span className="inline-flex items-center gap-1.5 rounded-full bg-red-100 px-3 py-1 text-xs font-bold uppercase tracking-wide text-red-700">
                    <TriangleAlert className="h-3.5 w-3.5" />
                    Malicious — likely phishing
                  </span>
                </div>
              </div>

              <div className="flex flex-wrap gap-1.5">
                {CONTROL_CHIPS.map((c, i) => (
                  <span
                    key={c.id}
                    className={`rounded-full px-2.5 py-1 text-[11px] font-semibold transition-opacity duration-500 ${
                      c.className
                    } ${i < visibleChips ? "opacity-100" : "opacity-0"}`}
                  >
                    {c.framework}: {c.id}
                  </span>
                ))}
              </div>

              <div
                className={`flex items-center gap-2 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm font-medium text-emerald-700 transition-opacity duration-500 ${
                  bannerVisible ? "opacity-100" : "opacity-0"
                }`}
              >
                <ShieldCheck className="h-4 w-4 shrink-0" />
                Auto-quarantined · sender blocked · logged as audit evidence
              </div>
            </div>
          </div>
    </div>
  );
}

export default function LiveSimulation() {
  const [runKey, setRunKey] = useState(0);

  return (
    <section className="bg-slate-50 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-navy sm:text-4xl">
            Watch Aegis in action
          </h2>
          <p className="mt-4 text-lg text-slate-600">
            A live simulation of a phishing email landing, being analyzed, and
            contained — in real time.
          </p>
        </div>

        <SimulationCard key={runKey} />

        <div className="mt-6 flex justify-center">
          <button
            type="button"
            onClick={() => setRunKey((k) => k + 1)}
            className="inline-flex items-center gap-2 rounded-full border border-slate-300 px-5 py-2.5 text-sm font-semibold text-slate-700 transition-colors hover:bg-white"
          >
            <RotateCcw className="h-4 w-4" />
            Run again
          </button>
        </div>
      </div>
    </section>
  );
}
