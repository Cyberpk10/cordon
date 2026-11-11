import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Bot,
  FileCheck2,
  FolderOpen,
  LayoutDashboard,
  Radar,
  ScanSearch,
  Settings,
  Siren,
  Sparkles,
  Target,
} from "lucide-react";

/** Every screen in the app, keyed by the same string ids the app has always used — the
 * dev-login initial-tab marker (see tabStorage.ts) stores one of these, so they must stay
 * stable even though "audit" and "reports" now share a single nav entry. */
export const TAB_VALUES = [
  "analyze",
  "cases",
  "dashboard",
  "detections",
  "early-warnings",
  "monitoring",
  "audit",
  "reports",
  "copilot",
  "autonomy",
  "simulations",
  "settings",
] as const;

export type Tab = (typeof TAB_VALUES)[number];

export function isTab(value: string | null): value is Tab {
  return TAB_VALUES.includes(value as Tab);
}

export interface NavItem {
  /** The tab this entry opens. */
  tab: Tab;
  label: string;
  icon: LucideIcon;
  /** Other tabs that should highlight this entry (sub-screens reached from it). */
  alsoActiveFor?: Tab[];
}

export interface NavSection {
  label: string;
  items: NavItem[];
}

export const NAV_SECTIONS: NavSection[] = [
  {
    label: "Detect",
    items: [
      { tab: "analyze", label: "Analyze", icon: ScanSearch },
      { tab: "cases", label: "Cases", icon: FolderOpen },
      { tab: "dashboard", label: "Dashboard", icon: LayoutDashboard },
      { tab: "detections", label: "Detections", icon: Radar },
    ],
  },
  {
    label: "Respond & prove",
    items: [
      { tab: "early-warnings", label: "Early Warnings", icon: Siren },
      { tab: "monitoring", label: "Monitoring", icon: Activity },
      { tab: "autonomy", label: "Autonomy", icon: Bot },
      { tab: "audit", label: "Audit & Reports", icon: FileCheck2, alsoActiveFor: ["reports"] },
      { tab: "copilot", label: "Copilot", icon: Sparkles },
      { tab: "simulations", label: "Simulations", icon: Target },
    ],
  },
];

/** Pinned at the bottom of the sidebar, next to the org/user block. */
export const SETTINGS_NAV_ITEM: NavItem = { tab: "settings", label: "Settings", icon: Settings };

export function isNavItemActive(item: NavItem, tab: Tab): boolean {
  return item.tab === tab || (item.alsoActiveFor?.includes(tab) ?? false);
}

/** Top-bar title and one-line subtitle for each screen. */
export const PAGE_META: Record<Tab, { title: string; subtitle: string }> = {
  analyze: {
    title: "Analyze",
    subtitle: "Score an email or activity log for phishing and intrusion signals.",
  },
  cases: { title: "Cases", subtitle: "Every analyzed message, its verdict, and its follow-up." },
  dashboard: {
    title: "Dashboard",
    subtitle: "Threat volume, verdict mix, and compliance coverage at a glance.",
  },
  detections: {
    title: "Detections",
    subtitle: "Intrusion and behavioral incidents correlated from activity events.",
  },
  "early-warnings": {
    title: "Early Warnings",
    subtitle: "Accounts whose combined signals suggest an attack is forming.",
  },
  monitoring: {
    title: "Monitoring",
    subtitle: "Continuous control monitoring and drift across frameworks.",
  },
  autonomy: { title: "Autonomy", subtitle: "Policy-gated automated response and its action log." },
  audit: {
    title: "Audit & Reports",
    subtitle: "Control evidence packs and board-ready compliance reports.",
  },
  reports: {
    title: "Audit & Reports",
    subtitle: "Control evidence packs and board-ready compliance reports.",
  },
  copilot: { title: "Copilot", subtitle: "Ask questions about your Cordon data in plain English." },
  simulations: {
    title: "Simulations",
    subtitle: "Phishing simulation campaigns and human-risk trends.",
  },
  settings: { title: "Settings", subtitle: "Email forwarding address and API keys." },
};
