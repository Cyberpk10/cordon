import { useState } from "react";
import type { CopilotQueryResponse } from "../../types/analysis";
import { Button, ErrorState } from "../ui";

interface CopilotMessageProps {
  question: string;
  response: CopilotQueryResponse | null;
  error: string | null;
}

export default function CopilotMessage({ question, response, error }: CopilotMessageProps) {
  const [showData, setShowData] = useState(false);

  return (
    <div className="flex flex-col gap-2">
      <div className="max-w-xl self-end rounded-lg bg-accent-fill px-4 py-2 text-sm text-fg-on-fill shadow-sm">
        {question}
      </div>

      <div className="max-w-2xl rounded-lg border border-line bg-surface-card p-4 shadow-sm">
        {error && <ErrorState message={error} />}
        {!error && !response && <p className="text-sm text-fg-secondary">Thinking…</p>}
        {response && (
          <>
            <p className="text-sm text-fg">{response.narrative}</p>
            <Button variant="link" className="mt-2" onClick={() => setShowData((value) => !value)}>
              {showData ? "Hide data" : "Show data"}
            </Button>
            {showData && (
              <div className="mt-2 rounded-lg border border-line bg-surface-panel p-3">
                <p className="text-xs font-semibold uppercase tracking-wide text-fg-secondary">
                  Query used
                </p>
                <p className="mt-1 break-all font-mono text-xs text-fg">
                  {response.template_used.template}({JSON.stringify(response.template_used.params)})
                </p>
                <p className="mt-3 text-xs font-semibold uppercase tracking-wide text-fg-secondary">
                  Retrieved figures
                </p>
                <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-words text-xs text-fg">
                  {JSON.stringify(response.result, null, 2)}
                </pre>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
