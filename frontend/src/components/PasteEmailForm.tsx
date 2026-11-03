import { useState } from "react";
import { ScanSearch } from "lucide-react";
import { Button, Textarea } from "./ui";

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
      <Textarea
        value={rawText}
        onChange={(event) => setRawText(event.target.value)}
        placeholder="Paste the raw email here — full headers and body, or just the subject and body text."
        aria-label="Raw email"
        rows={12}
        className="font-mono text-xs"
      />
      <Button
        type="submit"
        variant="primary"
        icon={ScanSearch}
        disabled={!rawText.trim()}
        loading={isLoading}
        loadingText="Analyzing…"
        className="self-start"
      >
        Analyze Email
      </Button>
    </form>
  );
}
