import type { PlaybookStep } from "../types/analysis";
import { Badge } from "./ui";

/** The framework controls a playbook step maps to, as compact chips. Shared by the
 * Response Playbook and Investigation panels. */
export default function ControlRefChips({ refs }: { refs: PlaybookStep["control_refs"] }) {
  if (refs.length === 0) return null;
  return (
    <div className="mt-2 flex flex-wrap gap-1">
      {refs.map((ref) => (
        <Badge key={`${ref.framework_key}-${ref.control_id}`} size="sm" title={ref.control_name}>
          {ref.framework_key}: {ref.control_id}
        </Badge>
      ))}
    </div>
  );
}
