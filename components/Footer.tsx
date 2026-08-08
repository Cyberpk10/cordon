import { ShieldCheck } from "lucide-react";

export default function Footer() {
  return (
    <footer className="border-t border-slate-200 bg-white">
      <div className="mx-auto flex max-w-7xl flex-col items-center justify-between gap-4 px-6 py-10 sm:flex-row">
        <div className="flex items-center gap-2 text-navy">
          <ShieldCheck className="h-5 w-5 text-brand-blue" />
          <span className="text-sm font-semibold tracking-tight">AEGIS</span>
        </div>

        <p className="text-sm text-slate-500">
          Paa Ekow Ansah (PK) ·{" "}
          <a
            href="mailto:paakowansah@icloud.com"
            className="font-medium text-brand-blue hover:underline"
          >
            paakowansah@icloud.com
          </a>
        </p>

        <p className="text-xs text-slate-400">
          © {new Date().getFullYear()} Aegis. All rights reserved.
        </p>
      </div>
    </footer>
  );
}
