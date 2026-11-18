"""The investigation agent's fixed, read-only tool set (M10 Stage 2).

Five tools, no others. Each one reads only data Cordon already holds for ONE account (the
ToolContext pins the account and the case), never fetches anything external, and never
writes. That is a structural property: there is no write path or action catalog here at
all, and the agent (app.investigation.agent) can only dispatch through TOOLS below.

Every tool returns plain-English lines; each line is registered in the EvidenceLedger as a
numbered evidence item (EV1, EV2, ...). Those ids are what every claim in the report must
cite (app.investigation.verify). Attacker-controlled text (subjects, URLs) is wrapped in
<untrusted> tags with angle brackets neutralized, the same treatment as the assistant's
prompts, so it can be shown to the model as data without becoming instructions.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable
from uuid import UUID

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.time import to_naive_utc
from app.db.models import Case
from app.geo.countries import COUNTRY_NAMES
from app.geo.lookup import lookup_country
from app.investigation.artifacts import build_artifacts
from app.mapping.framework_mapper import get_framework
from app.sender_baseline.aggregation import baseline_summary
from app.sender_baseline.loader import load_sender_baseline

MAX_UNTRUSTED_CHARS = 200
MAX_RELATED_SCAN = 500

# Shared mail-provider infrastructure: an IP here is the provider's outbound server, used by
# millions of senders. It says nothing about where the sender is, and two emails sharing it
# are not linked. (The hosted-mailbox caveat from the account-takeover work.)
HOSTED_MAIL_PROVIDERS = frozenset({
    "google.com", "googlemail.com", "outlook.com", "office365.com", "microsoft.com",
    "hotmail.com", "yahoo.com", "yahoodns.net", "icloud.com", "apple.com", "me.com",
    "amazonses.com", "sendgrid.net", "mailgun.org", "mailchimp.com", "mcsv.net",
    "protonmail.ch", "proton.me", "zoho.com", "fastmail.com", "messagingengine.com",
})

# Link domains so common across all mail that sharing one links nothing.
UBIQUITOUS_LINK_DOMAINS = frozenset({
    "google.com", "microsoft.com", "office.com", "outlook.com", "live.com", "apple.com",
    "linkedin.com", "facebook.com", "twitter.com", "x.com", "youtube.com", "instagram.com",
    "aka.ms", "w3.org", "gstatic.com", "googleapis.com", "windows.net", "sharepoint.com",
    "mailchimp.com", "list-manage.com", "zoom.us",
})

_LINK_INDICATOR_IDS = frozenset({
    "LINK_DISPLAY_HREF_MISMATCH", "LINK_SHORTENER", "LINK_SUSPICIOUS_TLD", "LINK_IP_LITERAL",
    "LINK_KNOWN_MALICIOUS", "SUSPICIOUS_LINK_PUBLIC_CHANNEL", "EXTERNAL_DM_WITH_LINK",
})


def untrusted(text: str | None, limit: int = MAX_UNTRUSTED_CHARS) -> str:
    if not text:
        return "(none)"
    return "<untrusted>" + text[:limit].replace("<", "‹").replace(">", "›") + "</untrusted>"


class EvidenceLedger:
    """Numbered evidence. Adding the same text twice returns the same id, so a repeated tool
    call never creates duplicate evidence. `key` lets the rules path find an item again
    (e.g. "indicator:ACCOUNT_TAKEOVER")."""

    def __init__(self) -> None:
        self.items: list[dict] = []
        self._by_text: dict[str, str] = {}
        self._by_key: dict[str, str] = {}

    def add(self, text: str, source: str, key: str | None = None) -> str:
        eid = self._by_text.get(text)
        if eid is None:
            eid = f"EV{len(self.items) + 1}"
            self.items.append({"id": eid, "text": text, "source": source})
            self._by_text[text] = eid
        if key:
            self._by_key.setdefault(key, eid)
        return eid

    def id_for(self, key: str) -> str | None:
        return self._by_key.get(key)

    def text_of(self, eid: str) -> str | None:
        for item in self.items:
            if item["id"] == eid:
                return item["text"]
        return None

    @property
    def ids(self) -> set[str]:
        return {item["id"] for item in self.items}


@dataclass
class ToolContext:
    db: Session
    account_id: UUID
    case: Case
    now: datetime  # naive UTC
    ledger: EvidenceLedger
    artifacts: dict | None = None
    # Filled by the tools as they run, read by app.investigation.assessment.
    facts: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ToolResult:
    tool: str
    args: dict
    evidence_ids: list[str]
    lines: list[str]  # what the model sees: "EVn: text", or a plain refusal line

    def as_text(self) -> str:
        return "\n".join(self.lines) if self.lines else "(no results)"


def resolve_artifacts(case: Case) -> dict | None:
    """Case.artifacts, or re-derived from the raw .eml for a Case saved before that column
    existed. None when neither is available (raw already purged)."""
    if case.artifacts:
        return case.artifacts
    if not case.raw_email_path:
        return None
    from app.parsing.eml_parser import parse_eml
    from app.sender_baseline.signals import extract_signals
    from app.storage.raw_email_store import load_raw_email

    raw = load_raw_email(case.raw_email_path)
    if raw is None:
        return None
    try:
        parsed = parse_eml(raw)
        return build_artifacts(parsed, extract_signals(parsed))
    except Exception:  # noqa: BLE001 - an unparseable stored email just means no artifacts.
        return None


def allowed_ips(ctx: ToolContext) -> list[str]:
    """IPs that actually appear on this case. enrich_ip refuses anything else, so the model
    can't use it as a general geo-lookup oracle."""
    ips: list[str] = []
    info = ctx.case.sender_ip_info or {}
    for key in ("originating_ip", "sending_ip"):
        ip = (info.get(key) or {}).get("ip")
        if ip and ip not in ips:
            ips.append(ip)
    if ctx.artifacts and ctx.artifacts.get("sending_ip") and ctx.artifacts["sending_ip"] not in ips:
        ips.append(ctx.artifacts["sending_ip"])
    return ips


def _register(ctx: ToolContext, tool: str, args: dict, texts: list[tuple[str, str | None]]) -> ToolResult:
    ids, lines = [], []
    for text, key in texts:
        eid = ctx.ledger.add(text, source=tool, key=key)
        ids.append(eid)
        lines.append(f"{eid}: {text}")
    return ToolResult(tool=tool, args=args, evidence_ids=ids, lines=lines)


def _refusal(tool: str, args: dict, message: str) -> ToolResult:
    return ToolResult(tool=tool, args=args, evidence_ids=[], lines=[f"(not available) {message}"])


# --- get_sender_baseline -------------------------------------------------------------------

def get_sender_baseline(ctx: ToolContext, sender: str | None = None) -> ToolResult:
    args = {"sender": sender}
    case_sender = (ctx.case.from_addr or "").lower()
    if not case_sender:
        return _refusal("get_sender_baseline", args, "This case has no sender address.")
    if sender and sender.strip().lower() != case_sender:
        return _refusal("get_sender_baseline", args, "Only this case's own sender can be looked up.")

    # What the detector saw at analysis time is authoritative for the verdict; fall back to
    # the live baseline only for a Case saved before baselines existed.
    summary = ctx.case.sender_baseline
    if not summary:
        summary = baseline_summary(
            load_sender_baseline(ctx.db, ctx.account_id, case_sender),
            lambda c: COUNTRY_NAMES.get(c, c),
        )
    from app.investigation.gather import _build_sender_intelligence

    intel = _build_sender_intelligence(ctx.db, ctx.account_id, ctx.case, ctx.now)
    ctx.facts["baseline_status"] = summary.get("status")
    ctx.facts["sender_classification"] = intel.classification if intel else None

    texts: list[tuple[str, str | None]] = [
        (f"Sender baseline for {case_sender} at analysis time: {summary.get('summary')}", "sender:baseline"),
    ]
    if intel is not None:
        texts.append((
            f"Sender domain {intel.domain} is classified {intel.classification} for this account "
            f"({intel.seen_count} prior email(s) in the lookback window"
            f"{', explicit trusted vendor' if intel.is_trusted_vendor else ''}).",
            "sender:classification",
        ))
    ato = ctx.case.account_takeover
    if ato:
        texts.append((f"Account-takeover finding ({ato.get('kind')}): {ato.get('explanation')}", "sender:ato"))
    return _register(ctx, "get_sender_baseline", args, texts)


# --- find_related_cases --------------------------------------------------------------------

def _match_reasons(case: Case, mine: dict | None, other: Case) -> list[str]:
    reasons: list[str] = []
    if case.from_addr and other.from_addr and case.from_addr.lower() == other.from_addr.lower():
        reasons.append("same sender")
    theirs = other.artifacts or {}
    if not mine:
        return reasons
    sig = mine.get("campaign_signature")
    if sig and sig == theirs.get("campaign_signature"):
        reasons.append("same campaign signature")
    shared = (set(mine.get("link_domains") or []) & set(theirs.get("link_domains") or [])) - UBIQUITOUS_LINK_DOMAINS
    if shared:
        reasons.append("shared link domain " + ", ".join(sorted(shared)[:3]))
    ip = mine.get("sending_ip")
    if (
        ip
        and ip == theirs.get("sending_ip")
        and (mine.get("sending_provider") or "") not in HOSTED_MAIL_PROVIDERS
    ):
        reasons.append(f"same sending IP {ip}")
    return reasons


def reason_kind(reason: str) -> str:
    for prefix, kind in (
        ("same campaign signature", "campaign signature"),
        ("shared link domain", "link domain"),
        ("same sending IP", "sending IP"),
        ("same sender", "sender"),
    ):
        if reason.startswith(prefix):
            return kind
    return reason


def find_related_cases(ctx: ToolContext) -> ToolResult:
    case = ctx.case
    cutoff = ctx.now - timedelta(days=settings.investigation_lookback_days)
    rows = (
        ctx.db.query(Case)
        .filter(
            Case.account_id == ctx.account_id,  # account isolation
            Case.id != case.id,
            Case.channel == "email",
            Case.created_at >= cutoff,
        )
        .order_by(Case.created_at.desc())
        .limit(MAX_RELATED_SCAN)
        .all()
    )
    related = []
    for row in rows:
        reasons = _match_reasons(case, ctx.artifacts, row)
        if reasons:
            related.append((row, reasons))
    # Strongest links first, then most recent.
    related.sort(key=lambda pair: (-len(pair[1]), -to_naive_utc(pair[0].created_at).timestamp()))
    related = related[: settings.investigation_max_related_cases]

    recipients = {a.lower() for a in (case.to_addresses or [])}
    for row, _ in related:
        recipients.update(a.lower() for a in (row.to_addresses or []))
    ctx.facts["related"] = [
        {
            "id": str(row.id),
            "created_at": to_naive_utc(row.created_at).isoformat(),
            "verdict": row.verdict,
            "score": row.score,
            "subject": row.subject,
            "to_addresses": list(row.to_addresses or []),
            "match_reasons": reasons,
        }
        for row, reasons in related
    ]

    if not related:
        texts = [(
            f"No other case for this account in the last {settings.investigation_lookback_days} "
            "days shares this sender, campaign signature, link domain or sending IP.",
            "related:summary",
        )]
    else:
        by_reason: dict[str, int] = {}
        for _, reasons in related:
            for r in reasons:
                label = reason_kind(r)
                by_reason[label] = by_reason.get(label, 0) + 1
        texts = [(
            f"{len(related)} related case(s) in the last {settings.investigation_lookback_days} days "
            f"({', '.join(f'{n} by {k}' for k, n in sorted(by_reason.items()))}), reaching "
            f"{len(recipients)} distinct recipient(s) including this email's.",
            "related:summary",
        )]
        for row, reasons in related:
            texts.append((
                f"Related case {row.id} on {to_naive_utc(row.created_at):%Y-%m-%d}: verdict={row.verdict}, "
                f"score={row.score}, linked by {'; '.join(reasons)}, sent to "
                f"{len(row.to_addresses or [])} recipient(s), subject {untrusted(row.subject)}.",
                f"related:{row.id}",
            ))
    if ctx.artifacts is None:
        texts.append((
            "Link and IP details for this case are no longer available (raw email purged), so "
            "related cases could only be matched by sender.",
            "related:limited",
        ))
    return _register(ctx, "find_related_cases", {}, texts)


# --- enrich_ip -----------------------------------------------------------------------------

def enrich_ip(ctx: ToolContext, ip: str | None = None) -> ToolResult:
    args = {"ip": ip}
    candidates = allowed_ips(ctx)
    if not candidates:
        return _refusal("enrich_ip", args, "No IP address was recorded for this case.")
    ip = (ip or candidates[0]).strip()
    if ip not in candidates:
        return _refusal("enrich_ip", args, "Only IP addresses found on this case can be enriched.")

    info = ctx.case.sender_ip_info or {}
    role = "originating client IP" if (info.get("originating_ip") or {}).get("ip") == ip else "sending server IP"
    geo = lookup_country(ip)
    provider = (ctx.artifacts or {}).get("sending_provider") if role == "sending server IP" else None
    if geo.status == "resolved":
        where = f"geolocates to {geo.country_name}"
    elif geo.status == "non_public":
        where = "is a private/non-public address"
    else:
        where = "has no geolocation in Cordon's offline dataset"
    texts: list[tuple[str, str | None]] = [(
        f"The {role} {ip} {where}" + (f"; the sending host belongs to {provider}" if provider else "") + ".",
        f"ip:{ip}",
    )]
    if provider and provider in HOSTED_MAIL_PROVIDERS:
        texts.append((
            f"{ip} is {provider} mail infrastructure shared by many senders: its location is the "
            "provider's server, not the sender's, and it does not link this email to others.",
            f"ip:{ip}:hosted",
        ))
    ctx.facts.setdefault("ips", {})[ip] = {
        "role": role, "country": geo.country_name, "provider": provider,
        "hosted": bool(provider and provider in HOSTED_MAIL_PROVIDERS),
    }
    return _register(ctx, "enrich_ip", args, texts)


# --- inspect_links -------------------------------------------------------------------------

def inspect_links(ctx: ToolContext) -> ToolResult:
    link_indicators = [i for i in ctx.case.indicators if i.get("id") in _LINK_INDICATOR_IDS]
    ctx.facts["link_indicator_ids"] = [i["id"] for i in link_indicators]
    texts: list[tuple[str, str | None]] = []
    if ctx.artifacts is None:
        texts.append(("The links in this email are no longer available (raw email purged).", "links:none"))
    else:
        domains = ctx.artifacts.get("link_domains") or []
        hrefs = ctx.artifacts.get("link_hrefs") or []
        if not hrefs:
            texts.append(("This email contains no links.", "links:none"))
        else:
            texts.append((
                f"This email contains {len(hrefs)} distinct link(s) to {len(domains)} domain(s): "
                + ", ".join(untrusted(d, 80) for d in domains[:8]) + ". Cordon never visits them.",
                "links:summary",
            ))
    for ind in link_indicators:
        evidence = "; ".join(untrusted(e, 160) for e in (ind.get("evidence") or [])[:3])
        texts.append((
            f"Link rule {ind['id']} matched ({ind.get('title')})" + (f": {evidence}" if evidence else "") + ".",
            f"links:{ind['id']}",
        ))
    if ctx.artifacts and (ctx.artifacts.get("link_hrefs")) and not link_indicators:
        texts.append(("No link rule matched any of these links.", "links:clean"))
    return _register(ctx, "inspect_links", {}, texts)


# --- framework_context ---------------------------------------------------------------------

def framework_context(ctx: ToolContext) -> ToolResult:
    mappings = ctx.case.framework_mappings or {}
    texts: list[tuple[str, str | None]] = []
    for key, refs in mappings.items():
        if not refs:
            continue
        fw = get_framework(key)
        name = fw.name if fw else key
        parts = []
        seen = set()
        for ref in refs:
            cid = ref.get("control_id")
            if cid in seen:
                continue
            seen.add(cid)
            parts.append(f"{cid} {ref.get('control_name')} (from {ref.get('indicator_id')})")
        texts.append((f"{name} mapping: " + "; ".join(parts[:8]) + ".", f"framework:{key}"))
    if not texts:
        texts.append(("No findings on this case map to a framework control.", "framework:none"))
    return _register(ctx, "framework_context", {}, texts)


# --- registry ------------------------------------------------------------------------------

TOOLS: dict[str, Callable[..., ToolResult]] = {
    "get_sender_baseline": get_sender_baseline,
    "find_related_cases": find_related_cases,
    "enrich_ip": enrich_ip,
    "inspect_links": inspect_links,
    "framework_context": framework_context,
}

# JSON schemas the agent sees. Arguments are optional and narrow by design.
TOOL_SCHEMAS: list[dict] = [
    {
        "name": "get_sender_baseline",
        "description": "This case's sender: baseline (history, usual country/provider, auth), domain classification, and any account-takeover finding.",
        "input_schema": {"type": "object", "properties": {"sender": {"type": "string"}}, "additionalProperties": False},
    },
    {
        "name": "find_related_cases",
        "description": "Other cases in this account sharing this case's sender, campaign signature, link domain or sending IP (is it one email or a wave?).",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "enrich_ip",
        "description": "Country and provider for an IP found on this case. Shared mail-provider IPs are not sender locations.",
        "input_schema": {"type": "object", "properties": {"ip": {"type": "string"}}, "additionalProperties": False},
    },
    {
        "name": "inspect_links",
        "description": "The email's link domains and which link rules matched. Nothing is fetched.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "framework_context",
        "description": "MITRE ATT&CK / NIST CSF / ISO 27001 / SOC 2 controls the findings map to.",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


def call_tool(ctx: ToolContext, name: str, args: dict | None) -> tuple[ToolResult, dict]:
    """Dispatch one call. Unknown tools and bad arguments return a refusal, never raise."""
    args = dict(args or {})
    started = time.monotonic()
    fn = TOOLS.get(name)
    if fn is None:
        result = _refusal(name, args, f"Unknown tool {name!r}.")
    else:
        allowed = {"get_sender_baseline": {"sender"}, "enrich_ip": {"ip"}}.get(name, set())
        clean = {k: (str(v)[:320] if v is not None else None) for k, v in args.items() if k in allowed}
        result = fn(ctx, **clean)
    trace = {
        "tool": name,
        "args": result.args,
        "evidence_ids": result.evidence_ids,
        "ms": int((time.monotonic() - started) * 1000),
    }
    return result, trace
