import clsx from "clsx";
import { LogOut } from "lucide-react";
import AegisLogo from "../AegisLogo";
import type { UserResponse } from "../../types/auth";
import {
  NAV_SECTIONS,
  SETTINGS_NAV_ITEM,
  isNavItemActive,
  type NavItem,
  type Tab,
} from "../../navigation";

interface SidebarContentProps {
  tab: Tab;
  onSelect: (tab: Tab) => void;
  user: UserResponse | null;
  onLogout: () => void;
  /** "responsive" is the docked sidebar: an icon rail at md, full labels at lg. "expanded"
   * always shows labels (used inside the mobile drawer). */
  variant: "responsive" | "expanded";
}

/** Labels collapse to screen-reader-only text in the md icon rail, so the rail stays
 * fully labeled for assistive tech while showing icons only. */
function labelClass(variant: SidebarContentProps["variant"]) {
  return variant === "responsive" ? "sr-only lg:not-sr-only lg:truncate" : "truncate";
}

function NavButton({
  item,
  tab,
  onSelect,
  variant,
}: {
  item: NavItem;
  tab: Tab;
  onSelect: (tab: Tab) => void;
  variant: SidebarContentProps["variant"];
}) {
  const active = isNavItemActive(item, tab);
  const Icon = item.icon;
  return (
    <button
      type="button"
      onClick={() => onSelect(item.tab)}
      aria-current={active ? "page" : undefined}
      title={variant === "responsive" ? item.label : undefined}
      className={clsx(
        "group relative flex w-full items-center gap-3 rounded-lg py-2 text-sm transition-colors duration-150",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
        variant === "responsive" ? "justify-center px-0 lg:justify-start lg:px-2.5" : "px-2.5",
        active
          ? "bg-surface-raised font-semibold text-fg"
          : "text-fg-secondary hover:bg-surface-raised/60 hover:text-fg"
      )}
    >
      {active && (
        <span
          aria-hidden="true"
          className="absolute inset-y-1.5 left-0 w-0.5 rounded-full bg-accent"
        />
      )}
      <Icon
        aria-hidden="true"
        className={clsx("h-4 w-4 shrink-0", active ? "text-accent" : "text-fg-muted group-hover:text-fg-secondary")}
      />
      <span className={labelClass(variant)}>{item.label}</span>
    </button>
  );
}

export default function SidebarContent({ tab, onSelect, user, onLogout, variant }: SidebarContentProps) {
  const responsive = variant === "responsive";

  return (
    <div className="flex h-full flex-col">
      <div
        className={clsx(
          "flex h-16 shrink-0 items-center gap-2.5 border-b border-line",
          responsive ? "justify-center lg:justify-start lg:px-4" : "px-4"
        )}
      >
        <AegisLogo className="h-7 w-7" />
        <span className={clsx("text-base font-semibold tracking-tight text-fg", responsive && "hidden lg:inline")}>
          Cordon
        </span>
      </div>

      <nav aria-label="Primary" className={clsx("flex-1 overflow-y-auto py-3", responsive ? "px-2 lg:px-3" : "px-3")}>
        {NAV_SECTIONS.map((section, index) => (
          <div key={section.label} className={index > 0 ? "mt-5" : undefined}>
            <p
              className={clsx(
                "px-2.5 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-fg-muted",
                responsive && "sr-only lg:not-sr-only lg:block"
              )}
            >
              {section.label}
            </p>
            {responsive && index > 0 && <div aria-hidden="true" className="mx-2 mb-2 border-t border-line lg:hidden" />}
            <ul className="flex flex-col gap-0.5">
              {section.items.map((item) => (
                <li key={item.tab}>
                  <NavButton item={item} tab={tab} onSelect={onSelect} variant={variant} />
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      <div className={clsx("shrink-0 border-t border-line py-3", responsive ? "px-2 lg:px-3" : "px-3")}>
        <NavButton item={SETTINGS_NAV_ITEM} tab={tab} onSelect={onSelect} variant={variant} />

        {user && (
          <div
            className={clsx(
              "mt-3 flex items-center gap-2.5",
              responsive ? "flex-col lg:flex-row lg:px-1" : "px-1"
            )}
          >
            <div
              aria-hidden="true"
              title={`${user.email} · ${user.role}`}
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-line-strong bg-surface-raised text-xs font-semibold uppercase text-fg"
            >
              {user.email.charAt(0)}
            </div>
            <div className={clsx("min-w-0 flex-1 leading-tight", responsive && "sr-only lg:not-sr-only")}>
              <p className="truncate text-sm font-semibold text-fg" title={user.account_name}>
                {user.account_name}
              </p>
              <p className="truncate text-xs text-fg-secondary" title={user.email}>
                {user.email}
              </p>
              <p className="text-[11px] capitalize text-fg-muted">{user.role}</p>
            </div>
            <button
              type="button"
              onClick={onLogout}
              aria-label="Log out"
              title="Log out"
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-fg-muted transition-colors duration-150 hover:bg-surface-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <LogOut aria-hidden="true" className="h-4 w-4" />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
