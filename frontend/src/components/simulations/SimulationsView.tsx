import { useState } from "react";
import CampaignsView from "./CampaignsView";
import HumanRiskView from "./HumanRiskView";

type SubTab = "campaigns" | "human-risk";

export default function SimulationsView() {
  const [subTab, setSubTab] = useState<SubTab>("campaigns");

  return (
    <div className="flex flex-col gap-6">
      <nav className="flex gap-1 border-b border-slate-200">
        {(["campaigns", "human-risk"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-4 py-2 text-sm font-medium transition ${
              subTab === t
                ? "border-b-2 border-indigo-600 text-indigo-700"
                : "text-slate-500 hover:text-slate-700"
            }`}
          >
            {t === "campaigns" ? "Campaigns" : "Human Risk"}
          </button>
        ))}
      </nav>

      {subTab === "campaigns" && <CampaignsView />}
      {subTab === "human-risk" && <HumanRiskView />}
    </div>
  );
}
