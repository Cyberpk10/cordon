"use client";

import { useState } from "react";
import {
  ChevronLeft,
  ChevronRight,
  TriangleAlert,
  Power,
  Undo2,
} from "lucide-react";

const CONTROL_BADGES: Record<string, string> = {
  MITRE: "bg-slate-100 text-slate-700",
  NIST: "bg-blue-100 text-blue-700",
  ISO: "bg-purple-100 text-purple-700",
  SOC2: "bg-emerald-100 text-emerald-700",
};

function ControlChip({ framework, id }: { framework: string; id: string }) {
  return (
    <span
      className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${CONTROL_BADGES[framework]}`}
    >
      {framework}: {id}
    </span>
  );
}

function StepEmailAnalysis() {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-slate-400">
          Case #4471
        </span>
        <span className="inline-flex items-center gap-1.5 rounded-full bg-red-100 px-3 py-1 text-xs font-bold uppercase tracking-wide text-red-700">
          <TriangleAlert className="h-3.5 w-3.5" />
          Malicious
        </span>
      </div>
      <div className="mt-4 flex items-baseline gap-2">
        <span className="text-4xl font-bold text-navy">92</span>
        <span className="text-sm text-slate-500">/ 100 risk score</span>
      </div>
      <dl className="mt-4 space-y-1 text-sm">
        <div>
          <dt className="inline font-medium text-slate-700">From: </dt>
          <dd className="inline text-slate-600">
            billing-support@paypaI-secure.com
          </dd>
        </div>
        <div>
          <dt className="inline font-medium text-slate-700">Subject: </dt>
          <dd className="inline text-slate-600">
            Urgent: verify your account within 24 hours
          </dd>
        </div>
      </dl>
      <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-3 text-xs leading-relaxed text-slate-600">
        <span className="font-semibold text-brand-blue">AI analyst:</span>{" "}
        Lookalike domain, urgency language, and a credential-harvesting link
        converge on a single verdict — quarantine recommended.
      </div>
    </div>
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
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h4 className="text-sm font-semibold text-navy">
        Findings mapped to controls
      </h4>
      <ul className="mt-4 space-y-3">
        {findings.map((f) => (
          <li
            key={f.title}
            className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50 p-3"
          >
            <span className="text-sm font-medium text-slate-700">
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

function StepDashboard() {
  const kpis = [
    { label: "Cases analyzed (30d)", value: "12,480" },
    { label: "Malicious rate", value: "3.2%" },
    { label: "Avg. response time", value: "1.8s" },
  ];
  const bars = [62, 40, 78, 55, 90, 48, 70];

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h4 className="text-sm font-semibold text-navy">Board dashboard</h4>
      <div className="mt-4 grid grid-cols-3 gap-3">
        {kpis.map((kpi) => (
          <div
            key={kpi.label}
            className="rounded-lg border border-slate-100 bg-slate-50 p-3"
          >
            <div className="text-lg font-bold text-navy">{kpi.value}</div>
            <div className="mt-0.5 text-[11px] text-slate-500">
              {kpi.label}
            </div>
          </div>
        ))}
      </div>
      <div className="mt-6 flex h-28 items-end gap-2">
        {bars.map((height, i) => (
          <div
            key={i}
            className="flex-1 rounded-t-md bg-gradient-to-t from-brand-blue to-brand-purple"
            style={{ height: `${height}%` }}
          />
        ))}
      </div>
      <div className="mt-2 flex justify-between text-[10px] text-slate-400">
        <span>Mon</span>
        <span>Tue</span>
        <span>Wed</span>
        <span>Thu</span>
        <span>Fri</span>
        <span>Sat</span>
        <span>Sun</span>
      </div>
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
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h4 className="text-sm font-semibold text-navy">
        Audit Mode — framework coverage
      </h4>
      <div className="mt-4 space-y-4">
        {frameworks.map((fw) => (
          <div key={fw.name}>
            <div className="flex justify-between text-xs font-medium text-slate-600">
              <span>{fw.name}</span>
              <span>{fw.coverage}%</span>
            </div>
            <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full rounded-full bg-gradient-to-r from-brand-blue to-brand-purple"
                style={{ width: `${fw.coverage}%` }}
              />
            </div>
          </div>
        ))}
      </div>
      <button
        type="button"
        className="mt-6 w-full rounded-lg bg-navy px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-navy-800"
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
      statusClass: "bg-emerald-100 text-emerald-700",
      undo: true,
    },
    {
      action: "Flag account for review",
      status: "Executed",
      statusClass: "bg-emerald-100 text-emerald-700",
      undo: true,
    },
    {
      action: "Disable session",
      status: "Pending approval",
      statusClass: "bg-amber-100 text-amber-700",
      undo: false,
    },
  ];

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-navy">
          Autonomous response
        </h4>
        <button
          type="button"
          className="inline-flex items-center gap-1.5 rounded-full bg-red-600 px-3 py-1.5 text-xs font-bold text-white"
        >
          <Power className="h-3.5 w-3.5" />
          Kill switch
        </button>
      </div>

      <div className="mt-4 grid grid-cols-4 gap-2">
        {levels.map((level) => (
          <div
            key={level}
            className={`rounded-lg border py-2 text-center text-xs font-bold ${
              level === activeLevel
                ? "border-brand-blue bg-brand-blue/10 text-brand-blue"
                : "border-slate-200 text-slate-400"
            }`}
          >
            {level}
          </div>
        ))}
      </div>

      <div className="mt-5 overflow-hidden rounded-lg border border-slate-100">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-50 text-slate-500">
            <tr>
              <th className="px-3 py-2 font-medium">Action</th>
              <th className="px-3 py-2 font-medium">Status</th>
              <th className="px-3 py-2 font-medium" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((row) => (
              <tr key={row.action}>
                <td className="px-3 py-2.5 text-slate-700">{row.action}</td>
                <td className="px-3 py-2.5">
                  <span
                    className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ${row.statusClass}`}
                  >
                    {row.status}
                  </span>
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
      "Every message gets a deterministic verdict plus an AI analyst narrative — in under 2 seconds.",
    render: StepEmailAnalysis,
  },
  {
    title: "Findings → controls",
    description:
      "Each indicator is automatically mapped to the frameworks your auditors already care about.",
    render: StepFindingsToControls,
  },
  {
    title: "Board dashboard",
    description:
      "Executives get a live view of volume, risk, and response time — no spreadsheets required.",
    render: StepDashboard,
  },
  {
    title: "Audit Mode",
    description:
      "One click turns months of detections into a signed, framework-organized evidence pack.",
    render: StepAuditMode,
  },
  {
    title: "Autonomous response",
    description:
      "Graduated autonomy contains threats automatically, with a hard kill switch always in reach.",
    render: StepAutonomy,
  },
];

export default function ProductTour() {
  const [step, setStep] = useState(0);
  const Active = STEPS[step].render;

  return (
    <section id="product-tour" className="bg-white py-24">
      <div className="mx-auto max-w-6xl px-6">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold tracking-tight text-navy sm:text-4xl">
            See Aegis in five steps
          </h2>
          <p className="mt-4 text-lg text-slate-600">
            From a landed phish to a signed audit pack — walk through the
            whole lifecycle.
          </p>
        </div>

        <div className="mt-14 grid items-center gap-10 lg:grid-cols-2">
          <div>
            <span className="text-xs font-bold uppercase tracking-wide text-brand-blue">
              Step {step + 1} of {STEPS.length}
            </span>
            <h3 className="mt-2 text-2xl font-semibold text-navy">
              {STEPS[step].title}
            </h3>
            <p className="mt-3 text-sm leading-relaxed text-slate-600">
              {STEPS[step].description}
            </p>

            <div className="mt-8 flex items-center gap-4">
              <button
                type="button"
                onClick={() => setStep((s) => Math.max(0, s - 1))}
                disabled={step === 0}
                className="inline-flex items-center gap-1 rounded-full border border-slate-300 px-4 py-2 text-sm font-semibold text-slate-700 transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-40"
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
                className="inline-flex items-center gap-1 rounded-full bg-navy px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-navy-800 disabled:cursor-not-allowed disabled:opacity-40"
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
                  className={`h-2 rounded-full transition-all ${
                    i === step
                      ? "w-8 bg-brand-blue"
                      : "w-2 bg-slate-300 hover:bg-slate-400"
                  }`}
                />
              ))}
            </div>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 sm:p-8">
            <Active />
          </div>
        </div>
      </div>
    </section>
  );
}
