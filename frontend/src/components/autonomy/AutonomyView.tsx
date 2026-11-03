import { useState } from "react";
import ActionsLog from "./ActionsLog";
import AutonomySettings from "./AutonomySettings";
import { TabPanel, Tabs } from "../ui";

type SubTab = "policy" | "log";

export default function AutonomyView() {
  const [subTab, setSubTab] = useState<SubTab>("policy");

  return (
    <div className="flex flex-col gap-6">
      <Tabs
        aria-label="Autonomy"
        idPrefix="autonomy"
        items={[
          { value: "policy", label: "Policy" },
          { value: "log", label: "Actions log" },
        ]}
        value={subTab}
        onChange={setSubTab}
      />

      <TabPanel idPrefix="autonomy" value={subTab}>
        {subTab === "policy" && <AutonomySettings />}
        {subTab === "log" && <ActionsLog />}
      </TabPanel>
    </div>
  );
}
