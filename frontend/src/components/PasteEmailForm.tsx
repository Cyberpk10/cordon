import { useState } from "react";

interface PasteEmailFormProps {
  onSubmit: (rawText: string) => void;
  isLoading: boolean;
}

export default function PasteEmailForm({ onSubmit, isLoading }: PasteEmailFormProps) {
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
        placeholder="Paste the raw email here — full headers and body, or just the subject and body text."
        rows={12}
        className="w-full rounded-lg border border-line-strong bg-surface-card p-3 font-mono text-xs text-fg shadow-sm focus:border-accent focus:outline-none focus:ring-1 focus:ring-accent"
      />
      <button
        type="submit"
        disabled={!rawText.trim() || isLoading}
        className="self-start whitespace-nowrap rounded-lg bg-accent-fill px-5 py-2 text-sm font-semibold text-fg-on-fill shadow-sm transition hover:bg-accent-fill-hover disabled:cursor-not-allowed disabled:bg-line-strong"
      >
        {isLoading ? "Analyzing…" : "Analyze Email"}
      </button>
    </form>
  );
}
