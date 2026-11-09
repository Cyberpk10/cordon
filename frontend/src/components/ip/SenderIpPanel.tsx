import { Info, Network } from "lucide-react";
import type { SenderIpInfo } from "../../types/analysis";
import { Badge, Card, CardBody, CardHeader } from "../ui";
import IpWithLocation, { GeoAttribution, usesDbIp } from "./IpWithLocation";

const SOURCE_TEXT: Record<NonNullable<SenderIpInfo["sending_ip_source"]>, string> = {
  spf_client_ip: "Seen by the receiving mail server (SPF check)",
  received_chain: "From the Received header chain",
};

/** The full "where did this email come from" panel for case detail and the analyze result.
 * Display-only: none of this affects the score. */
export default function SenderIpPanel({ info }: { info: SenderIpInfo | null | undefined }) {
  if (!info) return null;
  const { sending_ip, originating_ip, hops } = info;

  return (
    <Card padding="none">
      <CardHeader
        title={
          <span className="inline-flex items-center gap-2">
            <Network aria-hidden="true" className="h-4 w-4 text-fg-secondary" />
            Sending IP (from headers)
          </span>
        }
        description="Where the email's headers say it came from. Informational only; not used in the risk score."
      />
      <CardBody className="flex flex-col gap-4">
        {sending_ip ? (
          <div className="flex flex-col gap-1.5">
            <IpWithLocation ctx={sending_ip} />
            <div className="flex flex-wrap items-center gap-2 text-xs text-fg-secondary">
              {info.sending_ip_source && <span>{SOURCE_TEXT[info.sending_ip_source]}</span>}
              {info.sending_ip_confidence && (
                <Badge tone={info.sending_ip_confidence === "higher" ? "neutral" : "warning"} size="sm">
                  {info.sending_ip_confidence === "higher" ? "Higher confidence" : "Lower confidence"}
                </Badge>
              )}
            </div>
          </div>
        ) : (
          <p className="text-sm italic text-fg-muted">No public sending IP found in the headers.</p>
        )}

        {originating_ip && (
          <div className="flex flex-col gap-1">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-fg-muted">
              Originating client IP (X-Originating-IP)
            </span>
            <IpWithLocation ctx={originating_ip} />
            <span className="text-xs text-fg-secondary">Reported by the sender's mail provider. Easy to forge.</span>
          </div>
        )}

        <div className="flex gap-2 rounded-lg border border-line bg-surface-panel p-3 text-xs text-fg-secondary">
          <Info aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <p>
            This is the sending server's IP as recorded in the email headers. It is often the sender's mail
            provider rather than the attacker's own machine, and parts of the header chain can be forged. Treat
            it as a lead, not the attacker's exact location.
          </p>
        </div>

        {hops.length > 0 && (
          <details className="group text-xs">
            <summary className="cursor-pointer select-none font-semibold text-fg-secondary hover:text-fg">
              Received chain ({hops.length} hop{hops.length === 1 ? "" : "s"}, most recent first)
            </summary>
            <ol className="mt-2 flex flex-col gap-1 border-l border-line pl-3">
              {hops.map((hop) => (
                <li key={hop.index} className="break-all text-fg-secondary">
                  <span className="text-fg-muted">{hop.index + 1}.</span>{" "}
                  {!hop.from_host && !hop.ip ? (
                    <span className="italic text-fg-muted">internal hand-off, no sending host recorded</span>
                  ) : (
                    hop.from_host ?? "(unnamed host)"
                  )}{" "}
                  {hop.ip && (
                    <span className={hop.is_public ? "font-mono text-fg" : "font-mono text-fg-muted"}>
                      [{hop.ip}
                      {!hop.is_public && " · internal"}]
                    </span>
                  )}{" "}
                  {hop.by_host && <span className="text-fg-muted">→ {hop.by_host}</span>}
                </li>
              ))}
            </ol>
          </details>
        )}

        {usesDbIp([sending_ip, originating_ip]) && <GeoAttribution />}
      </CardBody>
    </Card>
  );
}
