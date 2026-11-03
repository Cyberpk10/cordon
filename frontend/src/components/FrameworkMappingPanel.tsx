import { useId, useState } from "react";
import type { FrameworkControlRef } from "../types/analysis";
import { EmptyState, TabPanel, Tabs } from "./ui";

const FRAMEWORK_LABELS: Record<string, string> = {
  mitre_attack: "MITRE ATT&CK",
  nist_csf: "NIST CSF",
  iso_27001: "ISO 27001",
  soc2: "SOC 2",
};

interface FrameworkMappingPanelProps {
  frameworkMappings: Record<string, FrameworkControlRef[]>;
}

export default function FrameworkMappingPanel({ frameworkMappings }: FrameworkMappingPanelProps) {
  const frameworkKeys = Object.keys(frameworkMappings);
  const [activeKey, setActiveKey] = useState(frameworkKeys[0] ?? "");
  const idPrefix = useId();

  if (frameworkKeys.length === 0) {
    return null;
  }

  const activeRefs = frameworkMappings[activeKey] ?? [];
  const dedupedControls = Array.from(
    new Map(activeRefs.map((ref) => [ref.control_id, ref])).values()
  );

  return (
    <div className="rounded-card border border-line bg-surface-card shadow-sm">
      <Tabs
        aria-label="Compliance framework"
        idPrefix={idPrefix}
        fitted
        items={frameworkKeys.map((key) => ({ value: key, label: FRAMEWORK_LABELS[key] ?? key }))}
        value={activeKey}
        onChange={setActiveKey}
        className="px-2"
      />
      <TabPanel idPrefix={idPrefix} value={activeKey} className="p-4">
        {dedupedControls.length === 0 ? (
          <EmptyState variant="inline" title="No controls mapped for this framework." />
        ) : (
          <ul className="flex flex-col gap-2">
            {dedupedControls.map((control) => (
              <li key={control.control_id} className="text-sm">
                <span className="font-mono font-semibold text-fg">{control.control_id}</span>
                <span className="text-fg-secondary"> — {control.control_name}</span>
              </li>
            ))}
          </ul>
        )}
      </TabPanel>
    </div>
  );
}
