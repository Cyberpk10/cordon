import Image from "next/image";
import Link from "next/link";
import Reveal from "@/components/motion/Reveal";

const PLATFORM_LINKS = [
  { label: "Email Threat Detection", href: "/#platform" },
  { label: "Early Warning", href: "/#early-warning" },
  { label: "Phishing Simulation & Training", href: "/#simulation" },
  { label: "Compliance Evidence", href: "/#platform" },
  { label: "Security & Compliance Reporting", href: "/#platform" },
  { label: "Investigation", href: "/#investigation" },
  { label: "Security & Trust", href: "/security" },
];

const COMPANY_LINKS = [
  { label: "About", href: "/#about-founder" },
  { label: "Try It", href: "/#playground" },
  { label: "Design Partner", href: "/#design-partner" },
];

function FooterColumn({
  title,
  links,
}: {
  title: string;
  links: { label: string; href: string }[];
}) {
  return (
    <div>
      <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
        {title}
      </h3>
      <ul className="mt-4 space-y-3 text-sm">
        {links.map((link) => (
          <li key={link.label}>
            <Link
              href={link.href}
              className="text-slate-400 transition-colors hover:text-white"
            >
              {link.label}
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Footer() {
  return (
    <footer className="border-t border-white/10 bg-navy-950">
      <div className="mx-auto max-w-7xl px-6 py-16">
        <Reveal className="grid grid-cols-1 gap-x-8 gap-y-12 sm:grid-cols-2 lg:grid-cols-5">
          <div className="sm:col-span-2">
            <div className="flex items-center gap-2 text-white">
              <Image
                src="/cordon-logo.png"
                alt="Cordon"
                width={32}
                height={32}
                className="h-6 w-6 rounded-[6px]"
              />
              <span className="text-sm font-semibold tracking-tight">
                Cordon Cybersecurity
              </span>
            </div>
            <p className="mt-3 max-w-xs text-sm text-slate-500">
              AI-native defensive security: phishing detection, autonomous
              containment, and audit-ready evidence.
            </p>
          </div>

          <FooterColumn title="Platform" links={PLATFORM_LINKS} />
          <FooterColumn title="Company" links={COMPANY_LINKS} />

          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
              Contact
            </h3>
            <ul className="mt-4 space-y-3 text-sm text-slate-400">
              <li>
                <a
                  href="mailto:paakowansah@icloud.com"
                  className="transition-colors hover:text-white"
                >
                  paakowansah@icloud.com
                </a>
              </li>
              <li>Tulsa, OK</li>
              <li>Dallas, TX</li>
            </ul>
          </div>
        </Reveal>

        <div className="mt-12 flex flex-col gap-4 border-t border-white/5 pt-6 text-xs text-slate-600 sm:flex-row sm:items-center sm:justify-between">
          <p>
            © {new Date().getFullYear()} Cordon Cybersecurity. All rights
            reserved.
          </p>
          <Link href="/privacy" className="transition-colors hover:text-white">
            Privacy
          </Link>
        </div>
      </div>
    </footer>
  );
}
