"use client";

import { useEffect, useId, useRef, useState } from "react";
import Link from "next/link";
import { Menu, X } from "lucide-react";
import { NAV_LINKS } from "@/components/navLinks";

/**
 * Below lg the desktop links don't fit, so they move behind a menu button. Closes on
 * Escape (returning focus to the button), on choosing a link, on a click outside, and
 * if the viewport grows past lg while open.
 */
export default function MobileMenu() {
  const [open, setOpen] = useState(false);
  const panelId = useId();
  const buttonRef = useRef<HTMLButtonElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        buttonRef.current?.focus();
      }
    };
    const onPointer = (e: PointerEvent) => {
      if (!rootRef.current?.contains(e.target as Node)) setOpen(false);
    };
    const wide = window.matchMedia("(min-width: 1024px)");
    const onWide = () => wide.matches && setOpen(false);
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointer);
    wide.addEventListener("change", onWide);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointer);
      wide.removeEventListener("change", onWide);
    };
  }, [open]);

  const itemClass =
    "block rounded-control px-3 py-2.5 text-base text-fg-secondary transition-colors duration-150 hover:bg-surface-raised hover:text-fg";

  return (
    <div ref={rootRef} className="lg:hidden">
      <button
        ref={buttonRef}
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        aria-label={open ? "Close menu" : "Open menu"}
        onClick={() => setOpen((v) => !v)}
        className="flex h-9 w-9 items-center justify-center rounded-control border border-line-strong bg-surface-card text-fg transition-colors duration-150 hover:bg-surface-raised"
      >
        {open ? <X aria-hidden className="h-4 w-4" /> : <Menu aria-hidden className="h-4 w-4" />}
      </button>

      <nav
        id={panelId}
        aria-label="Main"
        hidden={!open}
        className="absolute inset-x-0 top-full border-b border-line bg-surface-page shadow-2xl shadow-black/50"
      >
        <ul className="mx-auto flex max-w-7xl flex-col gap-1 px-3 py-3 sm:px-6">
          {NAV_LINKS.map((link) => (
            <li key={link.href}>
              {"route" in link ? (
                <Link href={link.href} className={itemClass} onClick={() => setOpen(false)}>
                  {link.label}
                </Link>
              ) : (
                <a href={link.href} className={itemClass} onClick={() => setOpen(false)}>
                  {link.label}
                </a>
              )}
            </li>
          ))}
        </ul>
      </nav>
    </div>
  );
}
