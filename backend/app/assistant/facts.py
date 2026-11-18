"""The grounded facts the assistant may answer from, built from Cordon's own analysis of one
email plus that email's own parsed data. Pure: no DB, no network, no detection logic. Every
value here was already produced by the shared pipeline (or read from a saved Case).

Each fact becomes one numbered evidence item (EV1, EV2, ...). Items carrying email-derived
text (sender, subject, links, attachment names, indicator evidence, the body) are flagged
`untrusted`: an attacker wrote that text, so app.assistant.llm delimits it as data and never
lets it read as instructions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.analysis.public_contract import (
    PublicVerdict,
    framework_tags,
    public_auth,
    public_verdict,
    ranked_indicators,
    summary_sentence,
)
from app.models.schemas import FrameworkControlRef, Indicator, Verdict
from app.parsing.eml_parser import ParsedEmail

# Same cap and reasoning as app.reasoning.llm_analyst._MAX_BODY_CHARS.
MAX_BODY_CHARS = 2000
MAX_LIST_ITEMS = 10
MAX_INDICATORS = 8


@dataclass(frozen=True)
class EmailFacts:
    verdict: PublicVerdict
    score: int
    summary: str
    indicators: list[Indicator]  # highest score first
    auth: dict[str, str]
    frameworks: list[str]
    from_address: str | None = None
    from_display: str | None = None
    reply_to_address: str | None = None
    subject: str | None = None
    link_domains: list[str] = field(default_factory=list)
    attachment_names: list[str] = field(default_factory=list)
    body_excerpt: str = ""
    # Cordon's own one-line summary of its history with this sender (app.sender_baseline),
    # e.g. "First contact: no baseline for this sender yet." Trusted: computed, not email text.
    sender_baseline: str | None = None
    # Cordon's investigation of this email (app.investigation.agent), reduced to trusted,
    # computed lines; the narrative is model-written, so it travels as untrusted text.
    investigation: dict | None = None


_CAMPAIGN_LINE = {
    "one_off": "No other email in this organisation's recent mail is linked to it (a one-off).",
    "possible_campaign": "It is linked to at least one other recent email (a possible campaign).",
    "wave": "It is part of a wave: {cases} linked emails reached {recipients} people in the last {days} days.",
}


def investigation_facts(report: dict | None) -> dict | None:
    """The parts of an investigation report the assistant may state: all computed by
    app.investigation.assessment, never by a model."""
    if not report:
        return None
    campaign = report["campaign"]
    conf = report["confidence"]
    rec = report["recommendation"]
    return {
        "confidence": conf["level"],
        "confidence_reason": conf["reasons"][0] if conf["reasons"] else "",
        "low_confidence_note": conf["reasons"][-1] if conf["level"] == "low" and conf["reasons"] else None,
        "campaign": campaign["status"],
        "campaign_line": _CAMPAIGN_LINE[campaign["status"]].format(
            cases=campaign["cases_in_window"], recipients=campaign["recipients_in_window"], days=campaign["window_days"]
        ),
        "hypothesis": report["hypothesis"]["label"],
        "recommended_action": rec["title"],
        "narrative": report.get("narrative") or "",
    }


@dataclass(frozen=True)
class EvidenceItem:
    id: str
    label: str
    trusted_text: str
    untrusted_text: str | None = None  # email-derived; always delimited, never instructions


def build_facts(
    *,
    verdict: Verdict,
    score: int,
    indicators: list[Indicator],
    framework_mappings: dict[str, list[FrameworkControlRef]],
    parsed: ParsedEmail,
    sender_baseline: dict | None = None,
    investigation_report: dict | None = None,
) -> EmailFacts:
    domains: list[str] = []
    for link in parsed.links:
        if link.href_domain and link.href_domain not in domains:
            domains.append(link.href_domain)
    return EmailFacts(
        verdict=public_verdict(verdict),
        score=score,
        summary=summary_sentence(verdict, score, indicators),
        indicators=ranked_indicators(indicators),
        auth=public_auth(parsed.auth_results),
        frameworks=framework_tags(framework_mappings),
        from_address=parsed.from_address,
        from_display=parsed.from_display,
        reply_to_address=parsed.reply_to_address,
        subject=parsed.subject,
        link_domains=domains[:MAX_LIST_ITEMS],
        attachment_names=[a.filename for a in parsed.attachments][:MAX_LIST_ITEMS],
        body_excerpt=(parsed.body_text or "")[:MAX_BODY_CHARS],
        sender_baseline=(sender_baseline or {}).get("summary"),
        investigation=investigation_facts(investigation_report),
    )


def auth_line(facts: EmailFacts) -> str:
    return ", ".join(f"{k.upper()} {facts.auth.get(k, 'none')}" for k in ("spf", "dkim", "dmarc"))


def build_evidence(facts: EmailFacts) -> list[EvidenceItem]:
    items: list[tuple[str, str, str | None]] = [
        (
            "verdict",
            f"Cordon's final verdict for this email: {facts.verdict}, risk score "
            f"{facts.score}/100. Summary: {facts.summary}",
            None,
        )
    ]
    if facts.indicators:
        for ind in facts.indicators[:MAX_INDICATORS]:
            items.append(
                (
                    "indicator",
                    f"Triggered indicator: {ind.title} (category {ind.category}, severity "
                    f"{ind.severity.value}, {ind.score:.0f} points). {ind.description}",
                    "; ".join(ind.evidence[:5]) or None,
                )
            )
    else:
        items.append(("indicator", "No phishing indicators were triggered for this email.", None))
    items.append(
        (
            "authentication",
            "Sender authentication, as recorded by the receiving mail server's "
            f"Authentication-Results header: {auth_line(facts)}.",
            None,
        )
    )
    if facts.frameworks:
        items.append(("frameworks", "Compliance framework mappings: " + ", ".join(facts.frameworks) + ".", None))

    sender = " ".join(
        part
        for part in (
            f'display name "{facts.from_display}"' if facts.from_display else "",
            f"address {facts.from_address}" if facts.from_address else "",
            f"reply-to {facts.reply_to_address}" if facts.reply_to_address else "",
        )
        if part
    )
    if facts.sender_baseline:
        items.append(("sender_history", "Cordon's history with this sender: " + facts.sender_baseline, None))
    if facts.investigation:
        inv = facts.investigation
        items.append((
            "investigation",
            f"Cordon's investigation of this email: {inv['confidence']} confidence in the verdict "
            f"({inv['confidence_reason']}) {inv['campaign_line']} Working hypothesis (not a "
            f"conclusion): {inv['hypothesis']}. Recommended response, not yet carried out: "
            f"{inv['recommended_action']}."
            + (f" {inv['low_confidence_note']}" if inv["low_confidence_note"] else ""),
            inv["narrative"] or None,
        ))
    items.append(("sender", "The email's From/Reply-To headers.", sender or "(none)"))
    items.append(("subject", "The email's subject line.", facts.subject or "(none)"))
    items.append(
        (
            "links",
            f"Domains the email links to ({len(facts.link_domains)} shown).",
            ", ".join(facts.link_domains) or "(no links)",
        )
    )
    items.append(
        (
            "attachments",
            f"Attachment file names ({len(facts.attachment_names)} shown).",
            ", ".join(facts.attachment_names) or "(no attachments)",
        )
    )
    return [
        EvidenceItem(id=f"EV{n}", label=label, trusted_text=trusted, untrusted_text=untrusted)
        for n, (label, trusted, untrusted) in enumerate(items, start=1)
    ]
