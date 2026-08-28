import { useEffect, useState } from "react";
import { getSimulationCampaign, sendSimulationCampaign } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import type { CampaignDetailResponse } from "../../types/analysis";
import AdminOnlyNote from "./AdminOnlyNote";
import { CampaignStatusBadge, RecipientStatusBadge } from "./SimulationStatusBadge";

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
      <button onClick={onBack} className="self-start text-sm font-medium text-indigo-600 hover:text-indigo-500">
        &larr; Back to campaigns
      </button>

      {error && <div className="rounded-lg border border-red-300 bg-red-50 p-4 text-sm text-red-700">{error}</div>}

      {!campaign && !error && <p className="text-sm text-slate-500">Loading campaign…</p>}

      {campaign && (
        <>
          <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-xl font-bold text-slate-900">{campaign.name}</h2>
                <p className="text-sm text-slate-500">Template: {campaign.template_id}</p>
              </div>
              <CampaignStatusBadge status={campaign.status} />
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1 text-sm text-slate-600 sm:grid-cols-2">
              {campaign.dry_run && (
                <div className="sm:col-span-2 rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-amber-800">
                  Dry run — Mailgun isn&apos;t configured on this deployment, so no real email
                  was sent. Preview links below simulate the recipient experience.
                </div>
              )}
              <div>
                <dt className="inline font-medium text-slate-700">From: </dt>
                <dd className="inline">{campaign.from_address ?? "—"}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Sent: </dt>
                <dd className="inline">{formatDate(campaign.sent_at)}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Authorized: </dt>
                <dd className="inline">{formatDate(campaign.authorized_at)}</dd>
              </div>
              <div>
                <dt className="inline font-medium text-slate-700">Recipients: </dt>
                <dd className="inline">{campaign.recipients.length}</dd>
              </div>
            </dl>
          </section>

          {campaign.status === "draft" && (
            <section className="rounded-xl border-2 border-amber-300 bg-amber-50 p-6 shadow-sm">
              <h3 className="text-lg font-semibold text-amber-900">Authorization required to send</h3>
              <p className="mt-2 text-sm text-amber-800">{AUTHORIZATION_STATEMENT}</p>
              <label className="mt-4 flex items-center gap-2 text-sm font-medium text-amber-900">
                <input
                  type="checkbox"
                  checked={authorizationChecked}
                  onChange={(event) => setAuthorizationChecked(event.target.checked)}
                  disabled={!isAdmin}
                />
                I accept the authorization statement above.
              </label>

              {sendError && <p className="mt-3 text-sm text-red-700">{sendError}</p>}

              <div className="mt-4 flex items-center gap-3">
                <button
                  onClick={handleSend}
                  disabled={!isAdmin || !authorizationChecked || isSending}
                  className="rounded-lg bg-red-600 px-6 py-2 text-sm font-bold text-white shadow-sm transition hover:bg-red-700 disabled:cursor-not-allowed disabled:bg-slate-300"
                >
                  {isSending ? "Sending…" : "Send campaign"}
                </button>
                {!isAdmin && <AdminOnlyNote />}
              </div>
            </section>
          )}

          <section className="overflow-hidden rounded-xl border border-slate-200 bg-white shadow-sm">
            <div className="border-b border-slate-200 bg-slate-900 px-6 py-3">
              <h3 className="text-base font-semibold text-white">Results</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-4 py-3 font-medium">Email</th>
                    <th className="px-4 py-3 font-medium">Department</th>
                    <th className="px-4 py-3 font-medium">Status</th>
                    <th className="px-4 py-3 font-medium">Sent</th>
                    <th className="px-4 py-3 font-medium">Clicked</th>
                    <th className="px-4 py-3 font-medium">Submitted</th>
                    <th className="px-4 py-3 font-medium">Reported</th>
                    <th className="px-4 py-3 font-medium">Preview</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-100">
                  {campaign.recipients.map((recipient) => (
                    <tr key={recipient.id}>
                      <td className="px-4 py-3 text-slate-800">{recipient.email}</td>
                      <td className="px-4 py-3 text-slate-600">{recipient.department ?? "—"}</td>
                      <td className="px-4 py-3">
                        <RecipientStatusBadge status={recipient.status} />
                      </td>
                      <td className="px-4 py-3 text-slate-500">{formatDate(recipient.sent_at)}</td>
                      <td className="px-4 py-3 text-slate-500">
                        {formatDate(recipient.clicked_at)}
                        {recipient.click_count > 1 && ` (×${recipient.click_count})`}
                      </td>
                      <td className="px-4 py-3 text-slate-500">{formatDate(recipient.submitted_at)}</td>
                      <td className="px-4 py-3 text-slate-500">
                        {formatDate(recipient.reported_at)}
                        {recipient.report_count > 1 && ` (×${recipient.report_count})`}
                      </td>
                      <td className="px-4 py-3">
                        {recipient.dry_run_tracking_url ? (
                          <a
                            href={recipient.dry_run_tracking_url}
                            target="_blank"
                            rel="noreferrer"
                            className="font-medium text-indigo-600 hover:text-indigo-500"
                          >
                            Open
                          </a>
                        ) : (
                          "—"
                        )}
                      </td>
                    </tr>
                  ))}
                  {campaign.recipients.length === 0 && (
                    <tr>
                      <td colSpan={8} className="px-4 py-8 text-center text-slate-500">
                        No recipients on this campaign.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </div>
  );
}
