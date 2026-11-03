import { useState } from "react";
import CampaignsView from "./CampaignsView";
import HumanRiskView from "./HumanRiskView";
import { TabPanel, Tabs } from "../ui";

type SubTab = "campaigns" | "human-risk";

export default function SimulationsView() {
  const [subTab, setSubTab] = useState<SubTab>("campaigns");

  return (
    <div className="flex flex-col gap-6">
      <Tabs
        aria-label="Simulations"
        idPrefix="simulations"
        items={[
          { value: "campaigns", label: "Campaigns" },
          { value: "human-risk", label: "Human Risk" },
        ]}
        value={subTab}
        onChange={setSubTab}
      />

      <TabPanel idPrefix="simulations" value={subTab}>
        {subTab === "campaigns" && <CampaignsView />}
        {subTab === "human-risk" && <HumanRiskView />}
      </TabPanel>
    </div>
  );
}
