import { useState } from "react";
import { MessageSquare, Send, ShieldCheck } from "lucide-react";
import { queryCopilot } from "../../api/client";
import type { CopilotQueryResponse } from "../../types/analysis";
import CopilotMessage from "./CopilotMessage";
import { Button, Card, EmptyState, Input } from "../ui";

interface ChatTurn {
  question: string;
  response: CopilotQueryResponse | null;
  error: string | null;
}

export default function CopilotView() {
  const [question, setQuestion] = useState("");
  const [turns, setTurns] = useState<ChatTurn[]>([]);
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    const trimmed = question.trim();
    if (!trimmed || isLoading) return;

    setIsLoading(true);
    setQuestion("");
    const turnIndex = turns.length;
    setTurns((prev) => [...prev, { question: trimmed, response: null, error: null }]);

    try {
      const response = await queryCopilot(trimmed);
      setTurns((prev) => prev.map((t, i) => (i === turnIndex ? { ...t, response } : t)));
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to get an answer.";
      setTurns((prev) => prev.map((t, i) => (i === turnIndex ? { ...t, error: message } : t)));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col gap-4">
        {turns.length === 0 && (
          <Card padding="none">
            <EmptyState
              icon={MessageSquare}
              title="Ask your first question"
              description={
                <>
                  Try &quot;how many malicious emails this month,&quot; &quot;how often was
                  alice@example.com targeted,&quot; or &quot;what&apos;s our MITRE coverage.&quot;
                </>
              }
            />
          </Card>
        )}
        {turns.map((turn, index) => (
          <CopilotMessage
            key={index}
            question={turn.question}
            response={turn.response}
            error={turn.error}
          />
        ))}
      </div>

      <div className="flex flex-col gap-2">
        <form onSubmit={handleSubmit} className="flex gap-3">
          <Input
            type="text"
            value={question}
            onChange={(event) => setQuestion(event.target.value)}
            placeholder="Ask a question about your Cordon data…"
            aria-label="Question"
            className="flex-1"
          />
          <Button
            variant="primary"
            icon={Send}
            type="submit"
            disabled={!question.trim()}
            loading={isLoading}
            loadingText="Asking…"
          >
            Ask
          </Button>
        </form>
        <p className="flex items-start gap-1.5 text-xs text-fg-muted">
          <ShieldCheck aria-hidden="true" className="mt-px h-3.5 w-3.5 shrink-0" />
          Every answer is grounded in a whitelisted, parameterized query — never free-form SQL — and
          the underlying figures are shown alongside the narrative.
        </p>
      </div>
    </div>
  );
}
