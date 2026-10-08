import Image from "next/image";
import Link from "next/link";

// Trimmed to the essentials (plus Security and About below) so the nav fits on one line.
// The remaining homepage sections (Early Warning, Training, Product Tour, Autonomy) are
// still reachable by scrolling the single page, right after Platform.
const LINKS = [
  { label: "Platform", href: "/#platform" },
  { label: "Try It", href: "/#playground" },
  { label: "Why Cordon", href: "/#why-aegis" },
];

const DEMO_MAILTO =
  "mailto:paakowansah@icloud.com?subject=Cordon%20demo%20request";

export default function Nav() {
  return (
    <header className="sticky top-0 z-50 border-b border-white/10 bg-navy/90 backdrop-blur supports-[backdrop-filter]:bg-navy/70">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-6 px-6">
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

        <nav className="hidden items-center gap-7 lg:flex">
          {LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="group relative text-sm font-medium whitespace-nowrap text-slate-300 transition-colors hover:text-white"
            >
              {link.label}
              <span className="absolute -bottom-1 left-0 h-px w-0 bg-brand-blue transition-all duration-300 group-hover:w-full" />
            </a>
          ))}
          <Link
            href="/security"
            className="group relative text-sm font-medium whitespace-nowrap text-slate-300 transition-colors hover:text-white"
          >
            Security
            <span className="absolute -bottom-1 left-0 h-px w-0 bg-brand-blue transition-all duration-300 group-hover:w-full" />
          </Link>
          <Link
            href="/#about-founder"
            className="group relative text-sm font-medium whitespace-nowrap text-slate-300 transition-colors hover:text-white"
          >
            About
            <span className="absolute -bottom-1 left-0 h-px w-0 bg-brand-blue transition-all duration-300 group-hover:w-full" />
          </Link>
        </nav>

        <a
          href={DEMO_MAILTO}
          className="btn-primary rounded-md px-4 py-2 text-sm font-semibold text-white"
        >
          Get a demo
        </a>
      </div>
    </header>
  );
}
