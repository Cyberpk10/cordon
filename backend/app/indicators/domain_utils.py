"""Shared, dependency-free domain helpers used by multiple indicator rules."""

from __future__ import annotations

import math
from collections import Counter

# Common multi-label public suffixes. Not exhaustive (no full Public Suffix List bundled to
# keep the engine dependency-free and fully offline) — good enough for the common brand/TLD
# cases M1 targets. Extend as needed in later milestones.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "co.jp", "co.in", "co.kr", "co.nz", "co.za",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg",
}


def registrable_domain(domain: str) -> str:
    """Best-effort extraction of the registrable ("brand") portion of a domain.

    e.g. "login.paypa1-secure.com" -> "paypa1-secure.com", "mail.example.co.uk" -> "example.co.uk"
    """
    domain = domain.lower().strip(".")
    labels = domain.split(".")
    if len(labels) <= 2:
        return domain
    last_two = ".".join(labels[-2:])
    if last_two in _MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return last_two


def levenshtein(a: str, b: str) -> int:
    """Standard edit distance, O(len(a)*len(b)), fine for short domain strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    previous_row = list(range(len(b) + 1))
    for i, char_a in enumerate(a, start=1):
        current_row = [i]
        for j, char_b in enumerate(b, start=1):
            insert_cost = current_row[j - 1] + 1
            delete_cost = previous_row[j] + 1
            substitute_cost = previous_row[j - 1] + (char_a != char_b)
            current_row.append(min(insert_cost, delete_cost, substitute_cost))
        previous_row = current_row
    return previous_row[-1]


def is_ip_literal_host(host: str) -> bool:
    parts = host.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


# Shared by app.indicators.domain_age_heuristic (sender domain) and
# app.indicators.trusted_sender_anomaly (link domains) — promoted here rather than one
# module importing the other's private helper, since both need the identical check against
# different inputs.
_MIN_LABEL_LENGTH_FOR_ENTROPY_CHECK = 8


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_randomly_generated(label: str, *, entropy_threshold: float) -> bool:
    """Zero-network proxy for "this label looks auto-generated" — high character-entropy
    plus a digit/letter mix, on labels long enough for entropy to be meaningful. Not a real
    WHOIS/RDAP registration-age check; see app.indicators.domain_age_heuristic's module
    docstring for why this codebase uses a heuristic instead of a live lookup."""
    if len(label) < _MIN_LABEL_LENGTH_FOR_ENTROPY_CHECK:
        return False
    has_digit_letter_mix = any(c.isdigit() for c in label) and any(c.isalpha() for c in label)
    if not has_digit_letter_mix:
        return False
    return _shannon_entropy(label) >= entropy_threshold
