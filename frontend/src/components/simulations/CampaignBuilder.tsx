import { useEffect, useState } from "react";
import { createSimulationCampaign, getSimulationTemplates, verifySimulationDomain } from "../../api/client";
import { useAuth } from "../../auth/AuthContext";
import type {
  CampaignDetailResponse,
  CampaignRecipientInput,
  DomainVerifyResponse,
  SimulationTemplateSummary,
} from "../../types/analysis";
import AdminOnlyNote from "./AdminOnlyNote";

interface CampaignBuilderProps {
  onCreated: (campaign: CampaignDetailResponse) => void;
}

function parseRecipients(text: string): CampaignRecipientInput[] {
  return text
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const [email, department] = line.split(",").map((part) => part.trim());
      return { email, department: department || null };
    });
}

export default function CampaignBuilder({ onCreated }: CampaignBuilderProps) {
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [domain, setDomain] = useState("");
  const [domainResult, setDomainResult] = useState<DomainVerifyResponse | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyError, setVerifyError] = useState<string | null>(null);

  const [templates, setTemplates] = useState<SimulationTemplateSummary[]>([]);
  const [templatesError, setTemplatesError] = useState<string | null>(null);
  const [selectedTemplateId, setSelectedTemplateId] = useState<string | null>(null);

  const [name, setName] = useState("");
  const [recipientsText, setRecipientsText] = useState("");
  const [createError, setCreateError] = useState<string | null>(null);
  const [isCreating, setIsCreating] = useState(false);

  useEffect(() => {
    getSimulationTemplates()
      .then((data) => {
        setTemplates(data.items);
        setSelectedTemplateId(data.items[0]?.id ?? null);
      })
      .catch((err) => setTemplatesError(err instanceof Error ? err.message : "Failed to load templates."));
  }, []);

  const handleVerify = async () => {
    if (!domain.trim()) return;
    setIsVerifying(true);
    setVerifyError(null);
    try {
      const result = await verifySimulationDomain(domain.trim());
      setDomainResult(result);
    } catch (err) {
      setVerifyError(err instanceof Error ? err.message : "Failed to verify domain.");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleCreate = async () => {
    if (!selectedTemplateId) {
      setCreateError("Choose a template.");
      return;
    }
    const recipients = parseRecipients(recipientsText);
    if (recipients.length === 0) {
      setCreateError("Add at least one recipient.");
      return;
    }
    setIsCreating(true);
    setCreateError(null);
    try {
      const campaign = await createSimulationCampaign({
        name: name.trim() || "Untitled campaign",
        template_id: selectedTemplateId,
        recipients,
      });
      onCreated(campaign);
    } catch (err) {
      setCreateError(err instanceof Error ? err.message : "Failed to create campaign.");
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-800">1. Verify a sending domain</h2>
          {!isAdmin && <AdminOnlyNote />}
        </div>
        <p className="mt-1 text-sm text-slate-500">
          A campaign can only target recipients on domains this account has proven DNS control
          of. Enter the domain, then add the returned TXT record with your DNS provider.
        </p>
        <div className="mt-4 flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm text-slate-600">
            Domain
            <input
              type="text"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              placeholder="corp.example.com"
              disabled={!isAdmin}
              className="w-64 rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700 disabled:cursor-not-allowed disabled:bg-slate-100"
            />
          </label>
          <button
            onClick={handleVerify}
            disabled={!isAdmin || isVerifying || !domain.trim()}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            {isVerifying ? "Checking…" : "Verify"}
          </button>
        </div>

        {verifyError && <p className="mt-3 text-sm text-red-700">{verifyError}</p>}

        {domainResult && (
          <div className="mt-4 rounded-lg border border-slate-200 bg-slate-50 p-4 text-sm">
            {domainResult.status === "verified" ? (
              <p className="font-medium text-emerald-700">
                &ldquo;{domainResult.domain}&rdquo; is verified.
              </p>
            ) : (
              <>
                <p className="font-medium text-slate-700">
                  Not verified yet. Add this TXT record, then click Verify again:
                </p>
                <dl className="mt-2 space-y-1 font-mono text-xs text-slate-600">
                  <div>
                    <dt className="inline text-slate-400">Name: </dt>
                    <dd className="inline">{domainResult.verification_record_name}</dd>
                  </div>
                  <div>
                    <dt className="inline text-slate-400">Value: </dt>
                    <dd className="inline">{domainResult.verification_record_value}</dd>
                  </div>
                </dl>
              </>
            )}
          </div>
        )}
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-800">2. Choose a template</h2>
        {templatesError && <p className="mt-2 text-sm text-red-700">{templatesError}</p>}
        <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3">
          {templates.map((template) => (
            <label
              key={template.id}
              className={`cursor-pointer rounded-lg border p-4 transition ${
                selectedTemplateId === template.id
                  ? "border-indigo-500 bg-indigo-50"
                  : "border-slate-200 hover:border-slate-300"
              }`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name="template"
                  checked={selectedTemplateId === template.id}
                  onChange={() => setSelectedTemplateId(template.id)}
                />
                <span className="font-semibold text-slate-800">{template.name}</span>
              </div>
              <p className="mt-1 text-xs text-slate-500">{template.subject}</p>
            </label>
          ))}
        </div>
      </section>

      <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-slate-800">3. Name it and add recipients</h2>
        <label className="mt-4 flex flex-col gap-1 text-sm text-slate-600">
          Campaign name
          <input
            type="text"
            value={name}
            onChange={(event) => setName(event.target.value)}
            placeholder="Q1 awareness test"
            className="w-full max-w-md rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700"
          />
        </label>
        <label className="mt-4 flex flex-col gap-1 text-sm text-slate-600">
          Recipients — one per line, optionally &ldquo;email, department&rdquo;
          <textarea
            value={recipientsText}
            onChange={(event) => setRecipientsText(event.target.value)}
            rows={6}
            placeholder={"alice@corp.example.com, Sales\nbob@corp.example.com"}
            className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-mono"
          />
        </label>

        {createError && <p className="mt-3 text-sm text-red-700">{createError}</p>}

        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={handleCreate}
            disabled={!isAdmin || isCreating}
            className="rounded-lg bg-indigo-600 px-6 py-2 text-sm font-semibold text-white shadow-sm transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-300"
          >
            {isCreating ? "Creating…" : "Create campaign"}
          </button>
          {!isAdmin && <AdminOnlyNote />}
        </div>
      </section>
    </div>
  );
}
