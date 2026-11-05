import Image from "next/image";
import Link from "next/link";
import MobileMenu from "@/components/MobileMenu";
import { DEMO_MAILTO, NAV_LINKS } from "@/components/navLinks";

const linkClass =
  "group relative text-sm font-normal whitespace-nowrap text-fg-secondary transition-colors duration-150 hover:text-fg";
const underline = (
  <span className="absolute -bottom-1 left-0 h-px w-0 bg-accent transition-[width] duration-150 group-hover:w-full" />
);

export default function Nav() {
  return (
    <header className="sticky top-0 z-50 border-b border-line bg-surface-page/90 backdrop-blur supports-[backdrop-filter]:bg-surface-page/80">
      {/* Same skip link as the app: visible only on keyboard focus. */}
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:absolute focus:top-3 focus:left-4 focus:z-[60] focus:rounded-control focus:bg-surface-card focus:px-4 focus:py-2 focus:text-sm focus:text-fg focus:ring-2 focus:ring-accent-text"
      >
        Skip to main content
      </a>
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between gap-6 px-6">
        <Link href="/" className="flex shrink-0 items-center gap-2 rounded-control text-fg">
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

        <nav aria-label="Main" className="hidden items-center gap-7 lg:flex">
          {NAV_LINKS.map((link) =>
            "route" in link ? (
              <Link key={link.href} href={link.href} className={linkClass}>
                {link.label}
                {underline}
              </Link>
            ) : (
              <a key={link.href} href={link.href} className={linkClass}>
                {link.label}
                {underline}
              </a>
            ),
          )}
        </nav>

        <div className="flex items-center gap-2">
          <a href={DEMO_MAILTO} className="btn btn-primary btn-md">
            Get a demo
          </a>
          <MobileMenu />
        </div>
      </div>
    </header>
  );
}
