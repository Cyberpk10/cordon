import clsx from "clsx";
import AuditView from "./AuditView";
import ReportsView from "../reports/ReportsView";

type AuditReportsTab = "audit" | "reports";

const SUB_TABS: { tab: AuditReportsTab; label: string }[] = [
  { tab: "audit", label: "Audit Mode" },
  { tab: "reports", label: "Security & Compliance Report" },
];

interface AuditReportsViewProps {
  /** Which sub-screen is showing — the app-level tab key itself, so "audit" and "reports"
   * remain independently addressable (e.g. by the dev-login initial-tab marker). */
  tab: AuditReportsTab;
  onSelect: (tab: AuditReportsTab) => void;
}

/** "Audit & Reports" nav entry: Audit Mode's per-framework evidence and the
 * cross-framework Security & Compliance Report, as two sub-tabs of one screen. */
export default function AuditReportsView({ tab, onSelect }: AuditReportsViewProps) {
  return (
    <div className="flex flex-col gap-6">
      <div role="tablist" aria-label="Audit & Reports" className="flex gap-1 border-b border-line">
        {SUB_TABS.map((item) => {
          const selected = item.tab === tab;
          return (
            <button
              key={item.tab}
              type="button"
              role="tab"
              id={`audit-reports-tab-${item.tab}`}
              aria-selected={selected}
              aria-controls="audit-reports-panel"
              onClick={() => onSelect(item.tab)}
              className={clsx(
                "-mb-px border-b-2 px-3 py-2 text-sm transition-colors duration-150",
                "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent",
                selected
                  ? "border-accent font-semibold text-fg"
                  : "border-transparent text-fg-secondary hover:text-fg"
              )}
            >
              {item.label}
            </button>
          );
        })}
      </div>
      <div id="audit-reports-panel" role="tabpanel" aria-labelledby={`audit-reports-tab-${tab}`}>
        {tab === "audit" ? <AuditView /> : <ReportsView />}
      </div>
    </div>
  );
}
