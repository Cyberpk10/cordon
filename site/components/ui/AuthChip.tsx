import { CheckCircle2, XCircle } from "lucide-react";

/** SPF/DKIM/DMARC result chip. `sm` is the hero panel's compact size. */
export default function AuthChip({
  label,
  result,
  size = "md",
}: {
  label: string;
  result: string;
  size?: "sm" | "md";
}) {
  const pass = result === "pass";
  const Icon = pass ? CheckCircle2 : XCircle;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-control border font-semibold ${
        size === "sm" ? "px-2.5 py-1 text-[11px]" : "px-3 py-1.5 text-xs"
      } ${pass ? "border-success/25 bg-success/5 text-success" : "border-danger/25 bg-danger/5 text-danger"}`}
    >
      <Icon aria-hidden className={size === "sm" ? "h-3 w-3" : "h-3.5 w-3.5"} />
      {label}: {result}
    </span>
  );
}
