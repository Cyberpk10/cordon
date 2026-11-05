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
    <header className="sticky top-0 z-50 border-b border-line bg-surface-page/90 backdrop-blur supports-[backdrop-filter]:bg-surface-page/80">
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-6 px-6">
        <Link href="/" className="flex shrink-0 items-center gap-2 text-fg">
          <Image
            src="/cordon-logo.png"
            alt="Cordon"
            width={32}
            height={32}
            className="h-7 w-7 rounded-[7px] sm:h-8 sm:w-8"
            priority
          />
          <span className="text-base font-semibold tracking-tight text-fg sm:text-lg">
            CORDON
          </span>
        </Link>

        <nav className="hidden items-center gap-7 lg:flex">
          {LINKS.map((link) => (
            <a
              key={link.href}
              href={link.href}
              className="group relative text-sm font-normal whitespace-nowrap text-fg-secondary transition-colors hover:text-fg"
            >
              {link.label}
              <span className="absolute -bottom-1 left-0 h-px w-0 bg-accent transition-all duration-300 group-hover:w-full" />
            </a>
          ))}
          <Link
            href="/security"
            className="group relative text-sm font-normal whitespace-nowrap text-fg-secondary transition-colors hover:text-fg"
          >
            Security
            <span className="absolute -bottom-1 left-0 h-px w-0 bg-accent transition-all duration-300 group-hover:w-full" />
          </Link>
          <Link
            href="/#about-founder"
            className="group relative text-sm font-normal whitespace-nowrap text-fg-secondary transition-colors hover:text-fg"
          >
            About
            <span className="absolute -bottom-1 left-0 h-px w-0 bg-accent transition-all duration-300 group-hover:w-full" />
          </Link>
        </nav>

        <a
          href={DEMO_MAILTO}
          className="btn-primary rounded-control px-4 py-2 text-sm font-semibold text-white"
        >
          Get a demo
        </a>
      </div>
    </header>
  );
}
