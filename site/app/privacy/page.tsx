import type { Metadata } from "next";
import type { ReactNode } from "react";
import Nav from "@/components/Nav";
import Footer from "@/components/Footer";
import Reveal from "@/components/motion/Reveal";

export const metadata: Metadata = {
  title: "Privacy Policy | Cordon",
  description:
    "What information Cordon collects, how we use it, and the choices you have.",
};

const CONTACT_MAILTO = "mailto:paakowansah@icloud.com";

const SUB_PROCESSORS = [
  { name: "Anthropic", purpose: "AI analysis (the analyst narrative)." },
  {
    name: "Render",
    purpose: "application hosting and managed database (United States).",
  },
  {
    name: "Vercel",
    purpose: "hosting for the web application and marketing site (United States).",
  },
  {
    name: "Mailgun",
    purpose: "transactional and authorized phishing-simulation email delivery.",
  },
  { name: "Cloudflare", purpose: "DNS and network protection." },
];

function H2({ children, id }: { children: string; id: string }) {
  return (
    <h2
      id={id}
      className="mt-14 scroll-mt-24 text-xl font-bold tracking-tight text-white sm:text-2xl"
    >
      {children}
    </h2>
  );
}

function P({ children }: { children: ReactNode }) {
  return <p className="mt-4 text-base leading-relaxed text-slate-300">{children}</p>;
}

export default function PrivacyPage() {
  return (
    <>
      <Nav />
      <main className="flex-1">
        <section className="relative overflow-hidden border-b border-white/5 bg-navy-950">
          <div
            className="glow-blob glow-breathe pointer-events-none absolute -top-32 left-1/2 h-96 w-96 -translate-x-1/2 bg-brand-blue/15"
            aria-hidden
          />
          <Reveal className="relative mx-auto max-w-3xl px-6 py-24 text-center">
            <h1 className="text-4xl font-bold tracking-tight text-white sm:text-5xl">
              Privacy Policy
            </h1>
            <p className="mt-6 text-sm font-medium text-slate-500">
              Last updated: October 15, 2026.
            </p>
          </Reveal>
        </section>

        <section className="bg-navy-950 pb-24">
          <Reveal className="mx-auto max-w-3xl px-6">
            <article>
              <P>
                Cordon Cybersecurity (&ldquo;Cordon,&rdquo; &ldquo;we,&rdquo; &ldquo;us,&rdquo;
                or &ldquo;our&rdquo;) operates the Cordon email-security, threat-detection, and
                compliance platform (the &ldquo;Service&rdquo;) at cordoncybersec.us. This
                Privacy Policy explains what information we collect, how we use it, and the
                choices you have.
              </P>
              <P>By using the Service you agree to the practices described here.</P>

              <H2 id="who-we-are">1. Who we are</H2>
              <P>
                The Service is provided by Cordon Cybersecurity, based in Tulsa, Oklahoma and
                Dallas, Texas, USA. For privacy questions, contact us at{" "}
                <a href={CONTACT_MAILTO} className="font-medium text-brand-blue hover:underline">
                  paakowansah@icloud.com
                </a>
                .
              </P>

              <H2 id="information-we-collect">2. Information we collect</H2>
              <P>
                <strong className="font-semibold text-white">Account information.</strong> When
                you create an account we collect your name, email address, organization name,
                and a securely hashed password. We do not store your password in plain text.
              </P>
              <P>
                <strong className="font-semibold text-white">
                  Content you submit for analysis.
                </strong>{" "}
                To analyze email you provide, we process message headers, sender and recipient
                addresses, authentication results (SPF, DKIM, DMARC), body text, links, and
                attachment metadata. To detect intrusions and data exfiltration, we process the
                activity and event logs you submit (for example login events, access events, and
                transfer volumes).
              </P>
              <P>
                <strong className="font-semibold text-white">Data minimization.</strong> By
                design, Cordon does not retain the raw content of analyzed emails by default. We
                retain the detection results, findings, risk scores, and control mappings needed
                to provide the Service and its audit evidence, and we minimize the underlying raw
                data we keep.
              </P>
              <P>
                <strong className="font-semibold text-white">Usage and technical data.</strong>{" "}
                We collect standard technical information such as log data, device and browser
                type, and timestamps to operate and secure the Service.
              </P>
              <P>
                <strong className="font-semibold text-white">
                  We do not sell your personal information, and we do not use your submitted
                  email or activity data to train third-party AI models.
                </strong>
              </P>

              <H2 id="how-we-use-information">3. How we use information</H2>
              <P>
                We use the information above to: provide and operate the Service; detect, score,
                and explain security threats; generate compliance and audit evidence; secure and
                maintain the platform; communicate with you about your account and the Service;
                and comply with legal obligations.
              </P>

              <H2 id="how-the-ai-analysis-works">4. How the AI analysis works</H2>
              <P>
                Cordon uses a third-party large-language-model provider (Anthropic) to generate
                the plain-English analyst narrative that accompanies a detection. Only the
                limited data needed to produce that explanation is sent to the provider, over an
                encrypted connection, and it is not used by the provider to train its models. The
                deterministic rules and machine-learning scoring run within Cordon&rsquo;s own
                systems.
              </P>

              <H2 id="sub-processors">5. Sub-processors</H2>
              <P>
                We rely on a small set of vetted service providers to run the Service. As of the
                date above these include:
              </P>
              <ul className="mt-4 space-y-2">
                {SUB_PROCESSORS.map((p) => (
                  <li key={p.name} className="flex gap-2 text-base leading-relaxed text-slate-300">
                    <span className="text-brand-blue">•</span>
                    <span>
                      <strong className="font-semibold text-white">{p.name}</strong>: {p.purpose}
                    </span>
                  </li>
                ))}
              </ul>
              <P>
                A current list of sub-processors is available on request. We require each to
                protect data consistent with this Policy.
              </P>

              <H2 id="phishing-simulation-data">6. Phishing simulation data</H2>
              <P>
                If your organization runs authorized phishing-simulation campaigns, Cordon
                records only whether each recipient opened, clicked, or reported a simulated
                message, and a resulting human-risk score.{" "}
                <strong className="font-semibold text-white">
                  Cordon never captures or stores real passwords or credentials entered on a
                  simulation page.
                </strong>{" "}
                There is structurally no field to store them. Simulations can only target
                recipients on a domain your organization has verified it controls, and require
                administrator authorization.
              </P>

              <H2 id="how-we-protect-information">7. How we protect information</H2>
              <P>
                We apply security measures appropriate to a security product, including:
                encryption of data in transit (TLS/HTTPS); Argon2id password hashing; strict
                per-account data isolation (one customer cannot access another&rsquo;s data);
                access controls and audit logging; and data minimization. No method of
                transmission or storage is 100% secure, but we work to protect your information
                and continually improve our posture.
              </P>

              <H2 id="data-retention">8. Data retention</H2>
              <P>
                We retain account information for as long as your account is active. Detection
                results and audit evidence are retained for the period needed to provide the
                Service and meet your compliance needs, after which they are deleted or
                anonymized. You may request deletion as described below.
              </P>

              <H2 id="your-rights-and-choices">9. Your rights and choices</H2>
              <P>
                Depending on where you live, you may have rights to access, correct, delete, or
                port your personal information, to object to or restrict certain processing, and
                to withdraw consent. To exercise any of these, contact us at{" "}
                <a href={CONTACT_MAILTO} className="font-medium text-brand-blue hover:underline">
                  paakowansah@icloud.com
                </a>
                . We will respond consistent with applicable law (including GDPR and CCPA/CPRA
                where they apply). Where your organization is our customer, we may direct certain
                requests to that organization as the data controller.
              </P>

              <H2 id="international-users">10. International users</H2>
              <P>
                The Service is operated in the United States. If you access it from outside the
                U.S., your information will be processed in the U.S. Where required, we use
                appropriate safeguards for international transfers.
              </P>

              <H2 id="children">11. Children</H2>
              <P>
                The Service is not directed to children and is intended for business use. We do
                not knowingly collect personal information from anyone under 18. Where Cordon
                processes data for a school or similar institution, it does so on that
                institution&rsquo;s behalf and under its direction.
              </P>

              <H2 id="changes-to-this-policy">12. Changes to this Policy</H2>
              <P>
                We may update this Policy from time to time. We will post the updated version
                with a new &ldquo;Last updated&rdquo; date and, for material changes, provide
                additional notice.
              </P>

              <H2 id="contact">13. Contact</H2>
              <P>
                Questions about this Policy or your data:{" "}
                <a href={CONTACT_MAILTO} className="font-medium text-brand-blue hover:underline">
                  paakowansah@icloud.com
                </a>
                . Cordon Cybersecurity, Tulsa, Oklahoma and Dallas, Texas, USA.
              </P>
            </article>
          </Reveal>
        </section>
      </main>
      <Footer />
    </>
  );
}
