import { Globe2, ShieldAlert } from "lucide-react";
import clsx from "clsx";
import type { ActorSourceIp, IpContext } from "../../types/analysis";
import { Badge } from "../ui";

/** Country text for an IP. Never guesses: anything unresolved says so plainly. */
export function locationText(ctx: IpContext): string {
  const { geo } = ctx;
  if (geo.status === "resolved" && geo.country_name) return geo.country_name;
  if (geo.status === "non_public") return "private / internal address";
  return "location unknown";
}

/** True when a country on screen came from the bundled DB-IP data, so its attribution must show. */
export function usesDbIp(contexts: (IpContext | null | undefined)[]): boolean {
  return contexts.some((c) => c?.geo.status === "resolved" && c.geo.source === "db-ip");
}

export function ThreatIntelBadge({ ctx }: { ctx: IpContext }) {
  if (!ctx.threat_intel) return null;
  return (
    <Badge
      tone="danger"
      size="sm"
      icon={ShieldAlert}
      title={`Matched threat-intel feed "${ctx.threat_intel.feed}" (snapshot ${ctx.threat_intel.snapshot_date})`}
    >
      {ctx.threat_intel.label}
    </Badge>
  );
}

/** Raw IP + country + any threat-intel label, on one wrapping line. */
export default function IpWithLocation({ ctx, className }: { ctx: IpContext; className?: string }) {
  const resolved = ctx.geo.status === "resolved";
  return (
    <span className={clsx("inline-flex flex-wrap items-center gap-x-2 gap-y-1", className)}>
      <span className="font-mono text-sm text-fg">{ctx.ip}</span>
      <span className={clsx("inline-flex items-center gap-1 text-sm", resolved ? "text-fg-secondary" : "italic text-fg-muted")}>
        <Globe2 aria-hidden="true" className="h-3.5 w-3.5 shrink-0" />
        {locationText(ctx)}
        {resolved && ctx.geo.source === "log" && <span className="text-xs text-fg-muted">(from log)</span>}
      </span>
      <ThreatIntelBadge ctx={ctx} />
    </span>
  );
}

export function GeoAttribution({ className }: { className?: string }) {
  return (
    <p className={clsx("text-[11px] text-fg-muted", className)}>
      Country-level only.{" "}
      <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer" className="underline hover:text-fg-secondary">
        IP geolocation by DB-IP
      </a>
    </p>
  );
}

/** Compact list of an actor's distinct source IPs (Early-Warning, activity-log summary). */
export function SourceIpList({ ips, emptyText = "No source IPs recorded." }: { ips: ActorSourceIp[]; emptyText?: string }) {
  if (ips.length === 0) return <p className="text-xs text-fg-secondary">{emptyText}</p>;
  return (
    <div className="flex flex-col gap-1.5">
      <ul className="flex flex-col gap-1.5">
        {ips.map((ip) => (
          <li key={ip.ip} className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <IpWithLocation ctx={ip} />
            <span className="text-xs text-fg-muted">
              {ip.event_count} event{ip.event_count === 1 ? "" : "s"}
            </span>
          </li>
        ))}
      </ul>
      {usesDbIp(ips) && <GeoAttribution />}
    </div>
  );
}
