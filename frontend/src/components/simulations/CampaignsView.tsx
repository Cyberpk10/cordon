import { useState } from "react";
import { ArrowLeft } from "lucide-react";
import type { CampaignDetailResponse } from "../../types/analysis";
import CampaignBuilder from "./CampaignBuilder";
import CampaignDetail from "./CampaignDetail";
import { CampaignStatusBadge } from "./SimulationStatusBadge";
import {
  Button,
  Card,
  EmptyState,
  TBody,
  TD,
  TH,
  THead,
  TR,
  Table,
  TableContainer,
  TableMessageRow,
} from "../ui";

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
        <Button variant="link" icon={ArrowLeft} className="self-start" onClick={() => setIsBuilding(false)}>
          Back to campaigns
        </Button>
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
        <p className="text-sm text-fg-secondary">
          Campaigns created this session. Reloading the page clears this list — pick a
          campaign right after creating it, or keep its link handy.
        </p>
        <Button variant="primary" onClick={() => setIsBuilding(true)}>
          New campaign
        </Button>
      </div>

      <Card padding="none" as="div">
        <TableContainer>
          <Table>
            <THead>
              <tr>
                <TH density="comfortable">Name</TH>
                <TH density="comfortable">Status</TH>
              </tr>
            </THead>
            <TBody>
              {campaigns.map((campaign) => (
                <TR
                  key={campaign.id}
                  onActivate={() => setSelectedId(campaign.id)}
                  aria-label={`Open campaign: ${campaign.name}`}
                >
                  <TD density="comfortable" className="font-semibold text-fg">{campaign.name}</TD>
                  <TD density="comfortable">
                    <CampaignStatusBadge status={campaign.status} />
                  </TD>
                </TR>
              ))}
              {campaigns.length === 0 && (
                <TableMessageRow colSpan={2}>
                  <EmptyState variant="inline" title="No campaigns yet this session." />
                </TableMessageRow>
              )}
            </TBody>
          </Table>
        </TableContainer>
      </Card>
    </div>
  );
}
