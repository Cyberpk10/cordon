import { useEffect, useState } from "react";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { getSimulationCampaign, sendSimulationCampaign } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import type { CampaignDetailResponse } from "../../types/analysis";
import AdminOnlyNote from "./AdminOnlyNote";
import { CampaignStatusBadge, RecipientStatusBadge } from "./SimulationStatusBadge";
import {
  Alert,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorState,
  LoadingState,
  TBody,
  TD,
  TH,
  THead,
  Table,
  TableContainer,
  TableMessageRow,
} from "../ui";

// Same wording as the backend's app.simulation.policy.AUTHORIZATION_STATEMENT — kept in
// sync manually since there's no endpoint that serves this text.
const AUTHORIZATION_STATEMENT =
  "I confirm this campaign targets only employees of my own organization, on domains this " +
  "account has verified control of, and that I am authorized to conduct this security-" +
  "awareness simulation.";

interface CampaignDetailProps {
  campaignId: string;
  onBack: () => void;
  onUpdated: (campaign: CampaignDetailResponse) => void;
}

function formatDate(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

export default function CampaignDetail({ campaignId, onBack, onUpdated }: CampaignDetailProps) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [campaign, setCampaign] = useState<CampaignDetailResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [authorizationChecked, setAuthorizationChecked] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setCampaign(null);
    setError(null);

    getSimulationCampaign(campaignId)
      .then((data) => {
        if (!cancelled) setCampaign(data);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load campaign.");
      });

    return () => {
      cancelled = true;
    };
  }, [campaignId]);

  const handleSend = async () => {
    setIsSending(true);
    setSendError(null);
    try {
      const updated = await sendSimulationCampaign(campaignId, true);
      setCampaign(updated);
      onUpdated(updated);
    } catch (err) {
      setSendError(err instanceof Error ? err.message : "Failed to send campaign.");
    } finally {
      setIsSending(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <Button variant="link" icon={ArrowLeft} className="self-start" onClick={onBack}>
        Back to campaigns
      </Button>

      {error && <ErrorState message={error} />}

      {!campaign && !error && <LoadingState label="Loading campaign…" />}

      {campaign && (
        <>
          <Card>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-xl font-semibold text-fg">{campaign.name}</h2>
                <p className="text-sm text-fg-secondary">Template: {campaign.template_id}</p>
              </div>
              <CampaignStatusBadge status={campaign.status} />
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-fg-secondary sm:grid-cols-2">
              {campaign.dry_run && (
                <Alert tone="warning" title="Dry run" className="sm:col-span-2">
                  Mailgun isn&apos;t configured on this deployment, so no real email was sent.
                  Preview links below simulate the recipient experience.
                </Alert>
              )}
              <div>
                <dt className="inline font-semibold text-fg">From: </dt>
                <dd className="inline">{campaign.from_address ?? "—"}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Sent: </dt>
                <dd className="inline">{formatDate(campaign.sent_at)}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Authorized: </dt>
                <dd className="inline">{formatDate(campaign.authorized_at)}</dd>
              </div>
              <div>
                <dt className="inline font-semibold text-fg">Recipients: </dt>
                <dd className="inline">{campaign.recipients.length}</dd>
              </div>
            </dl>
          </Card>

          {campaign.status === "draft" && (
            <Card tone="warning">
              <h3 className="flex items-center gap-2 text-base font-semibold text-warning">
                <ShieldAlert aria-hidden="true" className="h-4 w-4" />
                Authorization required to send
              </h3>
              <p className="mt-2 text-sm text-fg-secondary">{AUTHORIZATION_STATEMENT}</p>
              <label className="mt-4 flex items-center gap-2 text-sm font-semibold text-fg">
                <input
                  type="checkbox"
                  checked={authorizationChecked}
                  onChange={(event) => setAuthorizationChecked(event.target.checked)}
                  disabled={!isAdmin}
                />
                I accept the authorization statement above.
              </label>

              {sendError && <ErrorState message={sendError} className="mt-3" />}

              <div className="mt-4 flex items-center gap-3">
                <Button
                  variant="danger"
                  onClick={handleSend}
                  disabled={!isAdmin || !authorizationChecked}
                  loading={isSending}
                  loadingText="Sending…"
                >
                  Send campaign
                </Button>
                {!isAdmin && <AdminOnlyNote />}
              </div>
            </Card>
          )}

          <Card padding="none">
            <CardHeader title="Results" />
            <TableContainer>
              <Table>
                <THead>
                  <tr>
                    <TH>Email</TH>
                    <TH>Department</TH>
                    <TH>Status</TH>
                    <TH>Sent</TH>
                    <TH>Clicked</TH>
                    <TH>Submitted</TH>
                    <TH>Reported</TH>
                    <TH>Preview</TH>
                  </tr>
                </THead>
                <TBody>
                  {campaign.recipients.map((recipient) => (
                    <tr key={recipient.id}>
                      <TD className="text-fg">{recipient.email}</TD>
                      <TD className="text-fg-secondary">{recipient.department ?? "—"}</TD>
                      <TD>
                        <RecipientStatusBadge status={recipient.status} />
                      </TD>
                      <TD className="text-fg-secondary">{formatDate(recipient.sent_at)}</TD>
                      <TD className="text-fg-secondary">
                        {formatDate(recipient.clicked_at)}
                        {recipient.click_count > 1 && ` (×${recipient.click_count})`}
                      </TD>
                      <TD className="text-fg-secondary">{formatDate(recipient.submitted_at)}</TD>
                      <TD className="text-fg-secondary">
                        {formatDate(recipient.reported_at)}
                        {recipient.report_count > 1 && ` (×${recipient.report_count})`}
                      </TD>
                      <TD>
                        {recipient.dry_run_tracking_url ? (
                          <a
                            href={recipient.dry_run_tracking_url}
                            target="_blank"
                            rel="noreferrer"
                            className="font-semibold text-accent hover:text-accent-hover"
                          >
                            Open
                          </a>
                        ) : (
                          "—"
                        )}
                      </TD>
                    </tr>
                  ))}
                  {campaign.recipients.length === 0 && (
                    <TableMessageRow colSpan={8}>
                      <EmptyState variant="inline" title="No recipients on this campaign." />
                    </TableMessageRow>
                  )}
                </TBody>
              </Table>
            </TableContainer>
          </Card>
        </>
      )}
    </div>
  );
}
