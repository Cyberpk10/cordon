import { useState } from "react";
import ActionsLog from "./ActionsLog";
import AutonomySettings from "./AutonomySettings";

type SubTab = "policy" | "log";

export default function AutonomyView() {
  const [subTab, setSubTab] = useState<SubTab>("policy");

  return (
    <div className="flex flex-col gap-6">
      <nav className="flex gap-1 border-b border-line">
        {(["policy", "log"] as const).map((t) => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-4 py-2 text-sm font-semibold transition ${
              subTab === t
                ? "border-b-2 border-accent text-accent"
                : "text-fg-secondary hover:text-fg"
            }`}
          >
            {t === "policy" ? "Policy" : "Actions log"}
          </button>
        ))}
      </nav>

      {subTab === "policy" && <AutonomySettings />}
      {subTab === "log" && <ActionsLog />}
    </div>
  );
}
