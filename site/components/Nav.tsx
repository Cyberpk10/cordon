import Image from "next/image";
import Link from "next/link";

const LINKS = [
  { label: "Platform", href: "/#platform" },
  { label: "Early Warning", href: "/#early-warning" },
  { label: "Training", href: "/#simulation" },
  { label: "Product Tour", href: "/#product-tour" },
  { label: "Why Cordon", href: "/#why-aegis" },
  { label: "Autonomy", href: "/#autonomy" },
  { label: "About", href: "/#about-founder" },
];

const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Cordon%20demo%20request";

export default function Nav() {
  return (
    <header className="sticky top-0 z-50 border-b border-white/10 bg-navy/90 backdrop-blur supports-[backdrop-filter]:bg-navy/70">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-6">
        <Link href="/" className="flex shrink-0 items-center gap-2 text-white">
          <Image
            src="/brand/aegis-icon.svg"
            alt="Cordon"
            width={32}
            height={32}
            className="h-6 w-6 sm:h-7 sm:w-7"
            priority
          />
          <span className="text-base font-bold tracking-tight text-white sm:text-lg">
            CORDON
          </span>
        </Link>

        <nav className="hidden items-center gap-8 md:flex">
          {LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="text-sm font-medium text-slate-300 transition-colors hover:text-white"
            >
              {link.label}
            </a>
          ))}
          <Link
            href="/security"
            className="text-sm font-medium text-slate-300 transition-colors hover:text-white"
          >
            Security
          </Link>
        </nav>

        <a
          href={DEMO_MAILTO}
          className="rounded-md bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-blue-500"
        >
          Get a demo
        </a>
      </div>
    </header>
  );
}
