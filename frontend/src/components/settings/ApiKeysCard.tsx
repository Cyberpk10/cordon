import { useCallback, useEffect, useState } from "react";
import { Check, Copy, KeyRound } from "lucide-react";
import {
  createApiKey,
  listApiKeys,
  revokeApiKey,
  type ApiKeyCreated,
  type ApiKeySummary,
} from "../../api/client";
import { Alert, Badge, Button, Card, Input, LoadingState, useConfirm, useToast } from "../ui";

function formatDate(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "never";
}

/** Mint/revoke API keys for the public /v1 API (the Gmail add-on uses one). The raw key is
 * shown exactly once, right after creation; the server only keeps its hash. */
export default function ApiKeysCard() {
  const [keys, setKeys] = useState<ApiKeySummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("Gmail add-on");
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [copied, setCopied] = useState(false);
  const toast = useToast();
  const confirm = useConfirm();

  const load = useCallback(async () => {
    try {
      setKeys(await listApiKeys());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't load API keys.");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      const key = await createApiKey(name.trim() || "API key");
      setCreated(key);
      setCopied(false);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't create the key.");
    } finally {
      setCreating(false);
    }
  };

  const handleCopy = async () => {
    if (!created) return;
    try {
      await navigator.clipboard.writeText(created.key);
      setCopied(true);
      toast({ title: "API key copied" });
    } catch {
      // The key stays visible and selectable below.
    }
  };

  const handleRevoke = async (key: ApiKeySummary) => {
    const ok = await confirm({
      title: `Revoke "${key.name}"?`,
      description: "Anything using this key, such as the Gmail add-on, stops working immediately. This can't be undone.",
      confirmLabel: "Revoke key",
      tone: "danger",
    });
    if (!ok) return;
    try {
      await revokeApiKey(key.id);
      if (created?.id === key.id) setCreated(null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't revoke the key.");
    }
  };

  return (
    <Card as="div">
      <h2 className="flex items-center gap-2 text-base font-semibold text-fg">
        <KeyRound aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
        API keys
      </h2>
      <p className="mt-1 text-sm text-fg-secondary">
        For tools that call Cordon directly, like the Gmail add-on. A key analyzes email as you, into this
        account's Cases.
      </p>

      <div className="mt-4 flex flex-col gap-2 sm:flex-row">
        <Input
          aria-label="Key name"
          value={name}
          maxLength={80}
          onChange={(e) => setName(e.target.value)}
          className="sm:max-w-xs"
        />
        <Button variant="primary" loading={creating} onClick={handleCreate}>
          Create key
        </Button>
      </div>

      {created && (
        <Alert tone="warning" title="Copy this key now. You won't be able to see it again." className="mt-4">
          <div className="mt-2 flex items-center gap-2">
            <code className="flex-1 break-all rounded-control border border-line bg-surface-panel px-3 py-2 font-mono text-xs text-fg">
              {created.key}
            </code>
            <Button variant="secondary" icon={copied ? Check : Copy} onClick={handleCopy}>
              {copied ? "Copied" : "Copy"}
            </Button>
          </div>
        </Alert>
      )}

      {error && (
        <Alert tone="danger" className="mt-4">
          {error}
        </Alert>
      )}

      <div className="mt-4">
        {keys === null && !error ? (
          <LoadingState variant="inline" label="Loading keys…" />
        ) : keys && keys.length === 0 ? (
          <p className="text-xs text-fg-secondary">No API keys yet.</p>
        ) : (
          <ul className="flex flex-col divide-y divide-line">
            {(keys ?? []).map((k) => (
              <li key={k.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2 text-sm">
                <span className="font-medium text-fg">{k.name}</span>
                <code className="font-mono text-xs text-fg-secondary">{k.prefix}…</code>
                <span className="text-xs text-fg-muted">
                  created {formatDate(k.created_at)} · last used {formatDate(k.last_used_at)}
                </span>
                <span className="ml-auto">
                  {k.revoked_at ? (
                    <Badge tone="neutral" size="sm">
                      Revoked
                    </Badge>
                  ) : (
                    <Button variant="ghost" tone="danger" size="sm" onClick={() => handleRevoke(k)}>
                      Revoke
                    </Button>
                  )}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </Card>
  );
}
