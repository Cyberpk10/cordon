interface AIAnalystSummaryProps {
  narrative: string | null;
  model: string | null;
}

export default function AIAnalystSummary({ narrative, model }: AIAnalystSummaryProps) {
  if (!narrative) {
    return null;
  }

  return (
    <section className="rounded-xl border border-accent/25 bg-accent/10 p-6 shadow-sm">
      <div className="flex items-center justify-between gap-2">
        <h2 className="text-lg font-semibold text-accent">AI Analyst Summary</h2>
        {model && (
          <span className="rounded-full border border-accent/35 bg-surface-card px-2.5 py-0.5 text-xs font-semibold text-accent">
            {model}
          </span>
        )}
      </div>
      <p className="mt-2 text-sm text-accent">{narrative}</p>
    </section>
  );
}
