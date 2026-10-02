import { ShieldCheck } from "lucide-react";

const PRIVACY_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Cordon%20privacy%20inquiry";

export default function Footer() {
  return (
    <footer className="border-t border-white/10 bg-navy-950">
      <div className="mx-auto max-w-7xl px-6 py-12">
        <div className="flex flex-col gap-8 sm:flex-row sm:items-start sm:justify-between">
          <div>
            <div className="flex items-center gap-2 text-white">
              <ShieldCheck className="h-5 w-5 text-brand-blue" />
              <span className="text-sm font-semibold tracking-tight">
                Cordon Cybersecurity
              </span>
            </div>
            <p className="mt-2 max-w-xs text-sm text-slate-500">
              AI-native defensive security: phishing detection, autonomous
              containment, and audit-ready evidence.
            </p>
          </div>

          <nav className="flex gap-8 text-sm font-medium text-slate-400">
            <a href="#design-partner" className="transition-colors hover:text-white">
              Design Partner
            </a>
            <a href={PRIVACY_MAILTO} className="transition-colors hover:text-white">
              Privacy
            </a>
          </nav>

          <div className="text-sm text-slate-500">
            <p>Paa Ekow Ansah (Pk)</p>
            <a
              href="mailto:paakowansah@icloud.com"
              className="font-medium text-brand-blue hover:underline"
            >
              paakowansah@icloud.com
            </a>
          </div>
        </div>

        <div className="mt-10 border-t border-white/5 pt-6 text-xs text-slate-600">
          © {new Date().getFullYear()} Cordon Cybersecurity. All rights
          reserved.
        </div>
      </div>
    </footer>
  );
}
