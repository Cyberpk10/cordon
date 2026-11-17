import { History, ShieldAlert } from "lucide-react";
import type { AccountTakeoverFinding, SenderBaselineSummary } from "../../types/analysis";
import { Badge, Card, CardBody, CardHeader } from "../ui";

const STATUS: Record<SenderBaselineSummary["status"], { label: string; tone: "neutral" | "accent" | "success" | "danger" }> = {
  first_contact: { label: "First contact", tone: "neutral" },
  building: { label: "Building baseline", tone: "accent" },
  established: { label: "Established sender", tone: "success" },
  flagged: { label: "Previously malicious", tone: "danger" },
};

const INTENT_TEXT: Record<string, string> = {
  payment_change: "Payment / bank-detail change",
  invoice_redirect: "Invoice redirect",
  credential: "Credential request",
  mfa: "MFA / verification code request",
  gift_cards: "Gift cards",
  urgent_action: "High-pressure call to act",
};

/** The distinct account-takeover badge, for the top of a case or analyze result. */
export function AccountTakeoverBadge({ finding }: { finding: AccountTakeoverFinding | null | undefined }) {
  if (!finding) return null;
  return (
    <Badge tone="danger" size="lg" icon={ShieldAlert}>
      {finding.kind === "lateral" ? "Internal phishing: compromised colleague" : "Account takeover"}
    </Badge>
  );
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">{label}</span>
      <span className="text-sm text-fg">{children}</span>
    </div>
  );
}

/** Account-takeover finding (when it fired) and the sender baseline it was judged against.
 * Every string is rendered as text. */
export default function SenderBaselinePanel({
  finding,
  baseline,
}: {
  finding: AccountTakeoverFinding | null | undefined;
  baseline: SenderBaselineSummary | null | undefined;
}) {
  if (!finding && !baseline) return null;
  const status = baseline ? STATUS[baseline.status] : null;

  return (
    <>
      {finding && (
        <Card tone="danger" padding="md" aria-labelledby="ato-heading">
          <div className="flex flex-col gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <AccountTakeoverBadge finding={finding} />
              <h2 id="ato-heading" className="text-sm font-semibold text-fg">
                {finding.kind === "lateral"
                  ? "A known colleague's account is behaving out of pattern"
                  : "A known sender's account is behaving out of pattern"}
              </h2>
            </div>
            <p className="text-sm text-fg">{finding.explanation}</p>
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">
                  What deviated
                </span>
                <ul className="mt-1 list-disc space-y-1 pl-4 text-sm text-fg-secondary">
                  {finding.anomalies.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              </div>
              <div>
                <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">
                  What it asks for
                </span>
                <ul className="mt-1 list-disc space-y-1 pl-4 text-sm text-fg-secondary">
                  {finding.intents.map((i) => (
                    <li key={i}>{INTENT_TEXT[i] ?? i}</li>
                  ))}
                </ul>
              </div>
            </div>
          </div>
        </Card>
      )}

      {baseline && status && (
        <Card padding="none">
          <CardHeader
            title={
              <span className="inline-flex items-center gap-2">
                <History aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
                Sender baseline
              </span>
            }
            description="How this exact sender normally emails your organisation, built from mail Cordon has analyzed for this account."
            actions={
              <Badge tone={status.tone} size="sm">
                {status.label}
              </Badge>
            }
          />
          <CardBody className="flex flex-col gap-4">
            <p className="text-sm text-fg-secondary">{baseline.summary}</p>
            {baseline.status !== "first_contact" && (
              <div className="grid gap-4 sm:grid-cols-3">
                <Fact label="Prior messages">
                  {baseline.message_count}
                  {baseline.first_seen && (
                    <span className="text-fg-secondary">
                      {" "}
                      since {new Date(baseline.first_seen).toLocaleDateString()}
                    </span>
                  )}
                </Fact>
                <Fact label="Usually sent from">
                  {baseline.usual_countries.length ? baseline.usual_countries.join(", ") : "—"}
                  {baseline.usual_providers.length > 0 && (
                    <span className="text-fg-secondary"> via {baseline.usual_providers.join(", ")}</span>
                  )}
                </Fact>
                <Fact label="Authentication passed">
                  {baseline.auth_pass_count} of {baseline.message_count}
                </Fact>
              </div>
            )}
          </CardBody>
        </Card>
      )}
    </>
  );
}
