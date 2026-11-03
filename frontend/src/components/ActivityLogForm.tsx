import { useState } from "react";

interface ActivityLogFormProps {
  onSubmit: (rawText: string) => void;
  isLoading: boolean;
}

const PLACEHOLDER = `timestamp,account,source_ip,geo,result
2026-10-15T02:08:41Z,j.carter@example.org,185.220.101.44,RU,FAIL
2026-10-15T02:14:50Z,admin@example.org,185.220.101.44,RU,SUCCESS
2026-10-15T02:18:03Z,admin@example.org,185.220.101.44,RU,BULK_DOWNLOAD`;

export default function ActivityLogForm({ onSubmit, isLoading }: ActivityLogFormProps) {
  const [rawText, setRawText] = useState("");

  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (rawText.trim()) {
      onSubmit(rawText);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <textarea
        value={rawText}
        onChange={(event) => setRawText(event.target.value)}
        placeholder={PLACEHOLDER}
        rows={12}
        className="w-full rounded-lg border border-line-strong bg-surface-card p-3 font-mono text-xs text-fg shadow-sm focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
      />
      <p className="text-xs text-fg-secondary">
        Expected CSV header: <code className="font-mono">timestamp,account,source_ip,geo,result</code>
      </p>
      <button
        type="submit"
        disabled={!rawText.trim() || isLoading}
        className="self-start whitespace-nowrap rounded-lg bg-accent-fill px-5 py-2 text-sm font-semibold text-fg-on-fill shadow-sm transition hover:bg-accent-fill-hover disabled:cursor-not-allowed disabled:bg-line-strong"
      >
        {isLoading ? "Running…" : "Run"}
      </button>
    </form>
  );
}
