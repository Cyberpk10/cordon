import { useState } from "react";
import { Play } from "lucide-react";
import { Button, Textarea } from "./ui";

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
      <Textarea
        value={rawText}
        onChange={(event) => setRawText(event.target.value)}
        placeholder={PLACEHOLDER}
        aria-label="Activity log CSV"
        aria-describedby="activity-log-format"
        rows={12}
        className="font-mono text-xs"
      />
      <p id="activity-log-format" className="text-xs text-fg-secondary">
        Expected CSV header: <code className="font-mono">timestamp,account,source_ip,geo,result</code>
      </p>
      <Button
        type="submit"
        variant="primary"
        icon={Play}
        disabled={!rawText.trim()}
        loading={isLoading}
        loadingText="Running…"
        className="self-start"
      >
        Run
      </Button>
    </form>
  );
}
