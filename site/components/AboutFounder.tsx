import { BadgeCheck } from "lucide-react";

const SKILL_GROUPS = [
  {
    category: "Auditing & Assurance",
    skills: [
      "ISO 27001 Auditing",
      "Audit Planning",
      "Audit Management",
      "Audit Reporting",
      "Audit Follow-up",
      "Internal Audit",
      "Evidence Collection",
      "Nonconformity Assessment",
      "Corrective Action Management",
    ],
  },
  {
    category: "ISMS & Governance",
    skills: [
      "ISMS Implementation",
      "Information Security Governance",
      "Information Security Management",
      "Statement of Applicability",
      "Control Selection & Justification",
      "Annex A Controls",
      "Governance",
    ],
  },
  {
    category: "Risk Management",
    skills: [
      "Cybersecurity Risk Management",
      "Risk Analysis",
      "Risk Assessment",
      "Gap Analysis",
    ],
  },
  {
    category: "Compliance & Standards",
    skills: [
      "GRC Fundamentals",
      "Compliance Evaluation",
      "Continual Improvement",
      "Information Privacy",
      "Information Security",
      "Confidentiality",
    ],
  },
];

export default function AboutFounder() {
  return (
    <section id="about-founder" className="bg-navy-950 py-24">
      <div className="mx-auto grid max-w-7xl items-start gap-16 px-6 lg:grid-cols-2">
        <div>
          <h2 className="text-3xl font-bold tracking-tight text-white sm:text-4xl">
            About the Founder
          </h2>

          <div className="mt-8">
            <p className="text-xl font-semibold text-white">
              Paa Ekow Ansah (Pk)
            </p>
            <p className="mt-1 text-sm font-medium text-brand-blue">
              Founder, Cordon Cybersecurity AI Tool
            </p>
          </div>

          <div className="mt-6 space-y-4 text-base leading-relaxed text-slate-400">
            <p>
              Cordon was built by someone who came at the problem from the
              compliance side first.
            </p>
            <p>
              Paa Ekow Ansah is a Governance, Risk, and Compliance (GRC)
              professional and certified ISO/IEC 27001 Lead Auditor. His path
              into cybersecurity began in cloud engineering, where he
              developed a real appreciation for how technical systems are
              built. But his strength turned out to be the discipline that
              sits above the technology: risk analysis, governance, and
              security assurance at the organizational level. That
              realization led him to pivot deliberately into GRC, completing
              an intensive GRC program with GRC Mastery and earning the
              ISO/IEC 27001 Lead Auditor certification.
            </p>
            <p>
              The idea for Cordon came directly from that auditor&rsquo;s
              lens. Trained to plan and conduct ISMS audits, assessing Annex
              A controls, evaluating evidence, and mapping risk treatment to
              real requirements, he kept hitting the same gap. Security
              tools are good at catching threats, but the evidence auditors
              actually need lives in a completely separate world. An
              organization could pass its audit and still be one convincing
              phishing email away from a breach. And when that email landed,
              proving what happened and which controls applied meant
              assembling evidence by hand.
            </p>
            <p>
              Cordon was built to close that gap. It analyzes email the way
              a seasoned analyst would, then does the part most tools skip.
              It maps every detection to the frameworks organizations are
              measured against (ISO 27001, NIST CSF, SOC 2, and MITRE
              ATT&CK) and turns it into audit-ready evidence automatically.
              Detection that speaks the language of compliance. Put simply:
              it catches phishing like a top analyst, and reports it like an
              auditor.
            </p>
          </div>

          <div className="mt-8 inline-flex items-center gap-2 rounded-full border border-brand-blue/20 bg-brand-blue/10 px-4 py-1.5 text-xs font-semibold uppercase tracking-wide text-brand-blue">
            <BadgeCheck className="h-4 w-4" />
            Certified ISO/IEC 27001 Lead Auditor &middot; GRC Mastery
          </div>
        </div>

        <div className="rounded-2xl border border-white/10 bg-navy-900 p-10">
          <h3 className="text-xs font-bold uppercase tracking-wide text-brand-blue">
            Expertise
          </h3>
          <div className="mt-6 space-y-6">
            {SKILL_GROUPS.map((group) => (
              <div key={group.category}>
                <p className="text-sm font-semibold text-white">
                  {group.category}
                </p>
                <div className="mt-3 flex flex-wrap gap-2">
                  {group.skills.map((skill) => (
                    <span
                      key={skill}
                      className="inline-flex items-center rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs font-medium text-slate-200"
                    >
                      {skill}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
