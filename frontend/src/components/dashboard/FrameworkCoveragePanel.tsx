import type { FrameworkCoverage } from "../../types/analysis";
import { Card, CardHeader } from "../ui";

interface FrameworkCoveragePanelProps {
  coverage: FrameworkCoverage[];
}

export default function FrameworkCoveragePanel({ coverage }: FrameworkCoveragePanelProps) {
  return (
    <Card padding="none" as="div">
      <CardHeader title="Control Framework Coverage" />
      <div className="grid grid-cols-1 gap-4 p-6 sm:grid-cols-2 lg:grid-cols-4">
        {coverage.map((framework) => (
          <div key={framework.framework_key} className="rounded-lg border border-line p-4">
            <p className="text-sm font-semibold text-fg">{framework.framework_name}</p>
            <p className="mt-1 text-2xl font-semibold text-fg">{framework.coverage_pct}%</p>
            <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-line">
              <div
                className="h-full rounded-full bg-accent"
                style={{ width: `${Math.min(100, framework.coverage_pct)}%` }}
              />
            </div>
            <p className="mt-1 text-xs text-fg-secondary">
              {framework.covered_controls} / {framework.total_controls} controls
            </p>
          </div>
        ))}
      </div>
    </Card>
  );
}
