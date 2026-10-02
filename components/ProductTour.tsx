"use client";

import { useState } from "react";
import { ChevronLeft, ChevronRight, Power, Undo2 } from "lucide-react";
import ScreenshotFrame from "@/components/ScreenshotFrame";

function ControlChip({ framework, id }: { framework: string; id: string }) {
  return (
    <span className="rounded-md border border-white/10 bg-white/5 px-2 py-0.5 text-[11px] font-semibold text-slate-300">
      {framework}: {id}
    </span>
  );
}

function StepFindingsToControls() {
  const findings = [
    {
      title: "Lookalike domain",
      controls: [
        { framework: "MITRE", id: "T1566" },
        { framework: "NIST", id: "ID.RA-05" },
      ],
    },
    {
      title: "Urgency language",
      controls: [{ framework: "NIST", id: "PR.AT-01" }],
    },
    {
      title: "Credential-harvesting link",
      controls: [
        { framework: "ISO", id: "A.8.23" },
        { framework: "SOC2", id: "CC6.6" },
      ],
    },
    {
      title: "DKIM authentication fail",
      controls: [
        { framework: "MITRE", id: "T1656" },
        { framework: "ISO", id: "A.5.14" },
      ],
    },
  ];

  return (
    <div className="rounded-xl border border-white/10 bg-navy-900 p-6">
      <h4 className="text-sm font-semibold text-white">
        Findings mapped to controls
      </h4>
      <ul className="mt-4 space-y-3">
        {findings.map((f) => (
          <li
            key={f.title}
            className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-white/5 bg-white/[0.02] p-3"
          >
            <span className="text-sm font-medium text-slate-300">
              {f.title}
            </span>
            <div className="flex flex-wrap gap-1.5">
              {f.controls.map((c) => (
                <ControlChip key={c.id} framework={c.framework} id={c.id} />
              ))}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}

function StepAuditMode() {
  const frameworks = [
    { name: "MITRE ATT&CK", coverage: 92 },
    { name: "NIST CSF 2.0", coverage: 88 },
    { name: "ISO 27001", coverage: 85 },
    { name: "SOC 2", coverage: 90 },
  ];

  return (
    <div className="rounded-xl border border-white/10 bg-navy-900 p-6">
      <h4 className="text-sm font-semibold text-white">
        Audit Mode: framework coverage
      </h4>
      <div className="mt-4 space-y-4">
        {frameworks.map((fw) => (
          <div key={fw.name}>
            <div className="flex justify-between text-xs font-medium text-slate-400">
              <span>{fw.name}</span>
              <span>{fw.coverage}%</span>
            </div>
            <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-white/10">
              <div
                className="h-full rounded-full bg-brand-blue"
                style={{ width: `${fw.coverage}%` }}
              />
            </div>
          </div>
        ))}
      </div>
      <button
        type="button"
        className="mt-6 w-full rounded-md bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-blue-500"
      >
        Generate SOC 2 evidence pack →
      </button>
    </div>
  );
}

function StepAutonomy() {
  const levels = ["L0", "L1", "L2", "L3"];
  const activeLevel = "L2";
  const rows = [
    {
      action: "Quarantine email",
      status: "Executed",
      statusClass: "text-emerald-400",
      undo: true,
    },
    {
      action: "Flag account for review",
      status: "Executed",
      statusClass: "text-emerald-400",
      undo: true,
    },
    {
      action: "Disable session",
      status: "Pending approval",
      statusClass: "text-amber-400",
      undo: false,
    },
  ];

  return (
    <div className="rounded-xl border border-white/10 bg-navy-900 p-6">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-white">
          Autonomous response
        </h4>
        <button
          type="button"
          className="inline-flex items-center gap-1.5 rounded-md bg-red-500/10 px-3 py-1.5 text-xs font-bold text-red-400"
        >
          <Power className="h-3.5 w-3.5" />
          Kill switch
        </button>
      </div>

      <div className="mt-4 grid grid-cols-4 gap-2">
        {levels.map((level) => (
          <div
            key={level}
            className={`rounded-md border py-2 text-center text-xs font-bold ${
              level === activeLevel
                ? "border-brand-blue bg-brand-blue/10 text-brand-blue"
                : "border-white/10 text-slate-500"
            }`}
          >
            {level}
          </div>
        ))}
      </div>

      <div className="mt-5 overflow-hidden rounded-lg border border-white/10">
        <table className="w-full text-left text-xs">
          <thead className="bg-white/[0.03] text-slate-500">
            <tr>
              <th className="px-3 py-2 font-medium">Action</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium" />
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5">
            {rows.map((row) => (
              <tr key={row.action}>
                <td className="px-3 py-2.5 text-slate-300">{row.action}</td>
                <td className={`px-3 py-2.5 font-semibold ${row.statusClass}`}>
                  {row.status}
                </td>
                <td className="px-3 py-2.5 text-right">
                  {row.undo && (
                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-slate-500">
                      <Undo2 className="h-3 w-3" />
                      Undo
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const STEPS = [
  {
    title: "Email analysis",
    description:
      "Every message gets a deterministic verdict plus an AI analyst narrative in under 2 seconds.",
  },
  {
    title: "Findings → controls",
    description:
      "Each indicator is automatically mapped to the frameworks your auditors already care about.",
  },
  {
    title: "Board dashboard",
    description:
      "Executives get a live view of volume, risk, and response time. No spreadsheets required.",
  },
  {
    title: "Audit Mode",
    description:
      "One click turns months of detections into a signed, framework-organized evidence pack.",
  },
  {
    title: "Autonomous response",
    description:
      "Graduated autonomy contains threats automatically, with a hard kill switch always in reach.",
  },
];

export default function ProductTour({
  hasAnalyzeMalicious,
  hasDashboard,
}: {
  hasAnalyzeMalicious: boolean;
  hasDashboard: boolean;
}) {
  const [step, setStep] = useState(0);

  return (
    <section id="product-tour" className="bg-navy-900 py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            See Cordon in five steps
          </h2>
          <p className="mt-4 text-lg text-slate-400">
            From a landed phish to a signed audit pack: walk through the
            whole lifecycle.
          </p>
        </div>

        <div className="mt-14 grid items-center gap-10 lg:grid-cols-2">
          <div>
            <span className="text-xs font-bold uppercase tracking-wide text-brand-blue">
              Step {step + 1} of {STEPS.length}
            </span>
            <h3 className="mt-2 text-2xl font-semibold text-white">
              {STEPS[step].title}
            </h3>
            <p className="mt-3 text-sm leading-relaxed text-slate-400">
              {STEPS[step].description}
            </p>

            <div className="mt-8 flex items-center gap-4">
              <button
                type="button"
                onClick={() => setStep((s) => Math.max(0, s - 1))}
                disabled={step === 0}
                className="inline-flex items-center gap-1 rounded-md border border-white/15 px-4 py-2 text-sm font-semibold text-slate-300 transition-colors hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-40"
              >
                <ChevronLeft className="h-4 w-4" />
                Back
              </button>
              <button
                type="button"
                onClick={() =>
                  setStep((s) => Math.min(STEPS.length - 1, s + 1))
                }
                disabled={step === STEPS.length - 1}
                className="inline-flex items-center gap-1 rounded-md bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
                <ChevronRight className="h-4 w-4" />
              </button>
            </div>

            <div className="mt-6 flex gap-2">
              {STEPS.map((s, i) => (
                <button
                  key={s.title}
                  type="button"
                  aria-label={`Go to step ${i + 1}: ${s.title}`}
                  onClick={() => setStep(i)}
                  className={`h-1.5 rounded-full transition-all ${
                    i === step
                      ? "w-8 bg-brand-blue"
                      : "w-1.5 bg-white/15 hover:bg-white/25"
                  }`}
                />
              ))}
            </div>
          </div>

          <div>
            {step === 0 && (
              <ScreenshotFrame
                src={hasAnalyzeMalicious ? "/screenshots/analyze-malicious.png" : null}
                alt="Cordon's analysis verdict for a malicious phishing email"
                filename="analyze-malicious.png"
                aspectClass="aspect-[4/3]"
              />
            )}
            {step === 1 && <StepFindingsToControls />}
            {step === 2 && (
              <ScreenshotFrame
                src={hasDashboard ? "/screenshots/dashboard.png" : null}
                alt="Cordon's board dashboard"
                filename="dashboard.png"
                aspectClass="aspect-[4/3]"
              />
            )}
            {step === 3 && <StepAuditMode />}
            {step === 4 && <StepAutonomy />}
          </div>
        </div>
      </div>
    </section>
  );
}
