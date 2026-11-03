import { useState } from "react";

interface ForwardingAddressCardProps {
  forwardingAddress: string;
}

export default function ForwardingAddressCard({ forwardingAddress }: ForwardingAddressCardProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(forwardingAddress);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard API can be unavailable (permissions, insecure context) — the address is
      // still selectable/readable in the box below, so this is a soft failure, not an error.
    }
  };

  return (
    <div className="rounded-xl border border-line bg-surface-card p-6 shadow-sm">
      <h2 className="text-lg font-semibold text-fg">Your forwarding address</h2>
      <p className="mt-1 text-sm text-fg-secondary">
        Forward any suspicious email to this address — Cordon will analyze it automatically and
        add it to your Cases.
      </p>

      <div className="mt-4 flex items-center gap-2">
        <code className="flex-1 truncate rounded-lg border border-line bg-surface-panel px-3 py-2 font-mono text-sm text-fg">
          {forwardingAddress}
        </code>
        <button
          type="button"
          onClick={handleCopy}
          className="shrink-0 rounded-lg bg-accent-fill px-3 py-2 text-sm font-semibold text-fg-on-fill transition hover:bg-accent-fill-hover"
        >
          {copied ? "Copied!" : "Copy"}
        </button>
      </div>

      <p className="mt-3 text-xs text-fg-secondary">
        Tip: save this as a contact named "Report Phishing" so it's quick to forward to from
        your phone.
      </p>
    </div>
  );
}
