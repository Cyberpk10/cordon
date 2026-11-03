import AuditView from "./AuditView";
import ReportsView from "../reports/ReportsView";
import { TabPanel, Tabs } from "../ui";

type AuditReportsTab = "audit" | "reports";

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
      <Tabs
        aria-label="Audit & Reports"
        idPrefix="audit-reports"
        items={[
          { value: "audit", label: "Audit Mode" },
          { value: "reports", label: "Security & Compliance Report" },
        ]}
        value={tab}
        onChange={onSelect}
      />
      <TabPanel idPrefix="audit-reports" value={tab}>
        {tab === "audit" ? <AuditView /> : <ReportsView />}
      </TabPanel>
    </div>
  );
}
