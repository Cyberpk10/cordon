import { useState } from "react";
import type { CampaignDetailResponse } from "../../types/analysis";
import CampaignBuilder from "./CampaignBuilder";
import CampaignDetail from "./CampaignDetail";
import { CampaignStatusBadge } from "./SimulationStatusBadge";

// No GET /api/sim/campaigns list endpoint exists on the backend (Stage 1 shipped exactly
// six endpoints, lookup only by id) — this list is session-local, populated as campaigns
// are created here, not a persisted history. A page reload starts with an empty list;
// only a specific campaign's id can be looked up directly.
interface CampaignListEntry {
  id: string;
  name: string;
  status: CampaignDetailResponse["status"];
}

export default function CampaignsView() {
  const [campaigns, setCampaigns] = useState<CampaignListEntry[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [isBuilding, setIsBuilding] = useState(false);

  const upsertEntry = (campaign: CampaignDetailResponse) => {
    setCampaigns((prev) => {
      const entry = { id: campaign.id, name: campaign.name, status: campaign.status };
      const exists = prev.some((c) => c.id === campaign.id);
      return exists ? prev.map((c) => (c.id === campaign.id ? entry : c)) : [entry, ...prev];
    });
  };

  if (selectedId) {
    return (
      <CampaignDetail
        campaignId={selectedId}
        onBack={() => setSelectedId(null)}
        onUpdated={upsertEntry}
      />
    );
  }

  if (isBuilding) {
    return (
      <div className="flex flex-col gap-4">
        <button
          onClick={() => setIsBuilding(false)}
          className="self-start text-sm font-medium text-indigo-600 hover:text-indigo-500"
        >
          &larr; Back to campaigns
        </button>
        <CampaignBuilder
          onCreated={(campaign) => {
            upsertEntry(campaign);
            setIsBuilding(false);
            setSelectedId(campaign.id);
          }}
        />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-slate-500">
          Campaigns created this session. Reloading the page clears this list — pick a
          campaign right after creating it, or keep its link handy.
        </p>
        <button
          onClick={() => setIsBuilding(true)}
          className="whitespace-nowrap rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500"
        >
          New campaign
        </button>
      </div>

      <div className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
        <table className="w-full text-left text-sm">
          <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-6 py-3 font-medium">Name</th>
              <th className="px-6 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {campaigns.map((campaign) => (
              <tr
                key={campaign.id}
                onClick={() => setSelectedId(campaign.id)}
                className="cursor-pointer transition hover:bg-slate-50"
              >
                <td className="px-6 py-3 font-medium text-slate-800">{campaign.name}</td>
                <td className="px-6 py-3">
                  <CampaignStatusBadge status={campaign.status} />
                </td>
              </tr>
            ))}
            {campaigns.length === 0 && (
              <tr>
                <td colSpan={2} className="px-6 py-8 text-center text-slate-500">
                  No campaigns yet this session.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
