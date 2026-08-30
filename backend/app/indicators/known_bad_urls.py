"""Cross-references link destinations against a static, one-time-extracted snapshot of
PhishTank's verified-phishing-URL feed hostnames (M8 Stage 3a — see
scripts/extract_phishtank_hosts.py and app/indicators/data/phishtank_hosts.txt).

STALENESS LIMITATION (same spirit as lookalike_domain.py's curated-brand-list limitation,
which this codebase already accepts): PhishTank verifies and takes down reported phishing
infrastructure quickly, typically within days. This list is a point-in-time snapshot, not a
live feed — a match is real corroborating evidence when it hits, but the miss rate against
CURRENT phishing infrastructure grows every day past extraction. No periodic-refresh
mechanism exists — refresh by re-running scripts/extract_phishtank_hosts.py against a
freshly re-downloaded CSV (`python3 -m aegis_ml.download.phishtank`).

Purely offline: the hostname list is bundled as a static file, matched exactly (no network
calls), same architecture as brands.yaml/lookalike_domain.py.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from app.core.config import settings
from app.indicators.base import make_indicator
from app.channels.message import Message
from app.models.schemas import Indicator, Severity
from app.sender_history.aggregation import SenderHistorySnapshot

_HOSTS_PATH = Path(__file__).parent / "data" / "phishtank_hosts.txt"


@lru_cache(maxsize=1)
def _load_known_bad_hosts() -> frozenset[str]:
    if not _HOSTS_PATH.exists():
        return frozenset()
    lines = _HOSTS_PATH.read_text(encoding="utf-8").splitlines()
    return frozenset(line.strip().lower() for line in lines if line.strip() and not line.startswith("#"))


def evaluate(
    email: Message, sender_history: SenderHistorySnapshot | None = None
) -> list[Indicator]:
    if not settings.enable_known_bad_url_list:
        return []

    known_bad = _load_known_bad_hosts()
    if not known_bad:
        return []

    matched: list[str] = []
    for link in email.links:
        if link.href_domain and link.href_domain.lower() in known_bad:
            matched.append(f"{link.href_domain} ({link.href})")

    if not matched:
        return []

    return [
        make_indicator(
            id="LINK_KNOWN_PHISHING_HOST",
            category="link",
            title="Link matches a previously-reported phishing host",
            description=(
                "One or more links point to a hostname previously reported and verified as "
                "phishing infrastructure by PhishTank. This is a static, point-in-time "
                "snapshot — a match is strong corroborating evidence, but this list is not a "
                "live feed and will miss newly-registered attacker infrastructure."
            ),
            evidence=matched,
            severity=Severity.HIGH,
            score=25,
        )
    ]
