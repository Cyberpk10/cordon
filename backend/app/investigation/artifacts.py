"""Case artifacts: the few per-email facts the investigation tools correlate on (links, the
sending IP/provider, a campaign signature). Pure: no DB.

Computed once at analysis time and persisted on Case.artifacts so investigations keep
working after raw-email retention purge. For a Case saved before this column existed,
app.investigation.tools re-derives them from the stored raw .eml while it still exists.
"""

from __future__ import annotations

import hashlib
import re

from app.channels.message import Message
from app.indicators.domain_utils import registrable_domain
from app.sender_baseline.signals import MessageSignals

MAX_LINKS = 20

_REPLY_PREFIX_RE = re.compile(r"^\s*((re|fw|fwd|aw|wg|sv|tr)\s*(\[\d+\])?\s*:\s*)+", re.IGNORECASE)
_NON_WORD_RE = re.compile(r"[\W\d_]+", re.UNICODE)


def normalize_subject(subject: str | None) -> str:
    """Lowercased subject with reply/forward prefixes, digits, punctuation and whitespace
    removed, so "RE: Invoice #4471 overdue" and "Invoice #9902 overdue!" match."""
    if not subject:
        return ""
    return _NON_WORD_RE.sub("", _REPLY_PREFIX_RE.sub("", subject).lower())


def campaign_signature(subject: str | None, link_domains: list[str]) -> str | None:
    """Short hash of (normalized subject, sorted link domains). None when there is nothing
    distinctive to match on: an empty subject and no links would otherwise group every
    blank email together."""
    norm = normalize_subject(subject)
    if len(norm) < 6 and not link_domains:
        return None
    material = norm + "|" + ",".join(sorted(set(link_domains)))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def build_artifacts(email: Message, signals: MessageSignals | None) -> dict:
    hrefs: list[str] = []
    domains: list[str] = []
    for link in email.links:
        if link.href and link.href not in hrefs and len(hrefs) < MAX_LINKS:
            hrefs.append(link.href[:500])
        if link.href_domain:
            d = registrable_domain(link.href_domain.lower())
            if d not in domains:
                domains.append(d)
    return {
        "link_hrefs": hrefs,
        "link_domains": domains,
        "sending_ip": signals.sending_ip if signals else None,
        "sending_provider": signals.sending_provider if signals else None,
        "from_domain": signals.from_domain if signals else None,
        "campaign_signature": campaign_signature(getattr(email, "subject", None), domains),
    }
