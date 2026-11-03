import { useEffect, useRef, useState, type ReactNode } from "react";
import { Menu, X } from "lucide-react";
import clsx from "clsx";
import SidebarContent from "./Sidebar";
import type { UserResponse } from "../../types/auth";
import { PAGE_META, type Tab } from "../../navigation";

interface AppShellProps {
  tab: Tab;
  onSelectTab: (tab: Tab) => void;
  user: UserResponse | null;
  onLogout: () => void;
  /** Right-aligned top-bar actions for the current screen. */
  actions?: ReactNode;
  /** Narrow screens (forms, detail views) read better at a constrained width. */
  contentWidth?: "narrow" | "wide";
  children: ReactNode;
}

// Matches Tailwind's `md` breakpoint: at and above it the docked sidebar is visible, so
// the drawer is never needed.
const DOCKED_QUERY = "(min-width: 768px)";

export default function AppShell({
  tab,
  onSelectTab,
  user,
  onLogout,
  actions,
  contentWidth = "wide",
  children,
}: AppShellProps) {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);
  const meta = PAGE_META[tab];

  const closeDrawer = () => {
    setDrawerOpen(false);
    menuButtonRef.current?.focus();
  };

  const handleSelect = (next: Tab) => {
    onSelectTab(next);
    setDrawerOpen(false);
  };

  useEffect(() => {
    if (!drawerOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeDrawer();
    };
    const media = window.matchMedia(DOCKED_QUERY);
    const onMedia = () => media.matches && setDrawerOpen(false);
    document.addEventListener("keydown", onKey);
    media.addEventListener("change", onMedia);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const drawer = drawerRef.current;
    (
      drawer?.querySelector<HTMLElement>("button[aria-current='page']") ??
      drawer?.querySelector<HTMLElement>("nav button")
    )?.focus();
    return () => {
      document.removeEventListener("keydown", onKey);
      media.removeEventListener("change", onMedia);
      document.body.style.overflow = previousOverflow;
    };
  }, [drawerOpen]);

  // A new screen starts at the top, like a page navigation would.
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [tab]);

  return (
    <div className="min-h-screen bg-surface-page text-fg">
      {/* Docked sidebar: icon rail at md, full width at lg, hidden below md. */}
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-16 border-r border-line bg-surface-panel md:block lg:w-[184px]">
        <SidebarContent tab={tab} onSelect={handleSelect} user={user} onLogout={onLogout} variant="responsive" />
      </aside>

      {/* Mobile drawer. */}
      {drawerOpen && (
        <div className="fixed inset-0 z-40 md:hidden" role="dialog" aria-modal="true" aria-label="Navigation">
          <button
            type="button"
            aria-label="Close navigation"
            tabIndex={-1}
            onClick={closeDrawer}
            className="absolute inset-0 h-full w-full cursor-default bg-black/60"
          />
          <div
            ref={drawerRef}
            className="absolute inset-y-0 left-0 w-[264px] max-w-[85vw] border-r border-line bg-surface-panel shadow-2xl"
          >
            <button
              type="button"
              onClick={closeDrawer}
              aria-label="Close navigation"
              className="absolute right-3 top-4 flex h-8 w-8 items-center justify-center rounded-lg text-fg-secondary transition-colors duration-150 hover:bg-surface-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <X aria-hidden="true" className="h-4 w-4" />
            </button>
            <SidebarContent tab={tab} onSelect={handleSelect} user={user} onLogout={onLogout} variant="expanded" />
          </div>
        </div>
      )}

      <div className="md:pl-16 lg:pl-[184px]">
        <header className="sticky top-0 z-20 border-b border-line bg-surface-page/85 backdrop-blur">
          <div className="flex min-h-16 items-center gap-3 px-4 py-3 sm:px-6 lg:px-8">
            <button
              ref={menuButtonRef}
              type="button"
              onClick={() => setDrawerOpen(true)}
              aria-label="Open navigation"
              aria-expanded={drawerOpen}
              className="-ml-1 flex h-9 w-9 shrink-0 items-center justify-center rounded-lg text-fg-secondary transition-colors duration-150 hover:bg-surface-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent md:hidden"
            >
              <Menu aria-hidden="true" className="h-5 w-5" />
            </button>
            <div className="min-w-0 flex-1">
              <h1 className="truncate text-lg font-semibold leading-tight text-fg">{meta.title}</h1>
              <p className="truncate text-sm text-fg-secondary">{meta.subtitle}</p>
            </div>
            {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
          </div>
        </header>

        <main className="px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
          <div className={clsx("mx-auto w-full", contentWidth === "narrow" ? "max-w-3xl" : "max-w-6xl")}>
            {children}
          </div>
        </main>
      </div>
    </div>
  );
}
