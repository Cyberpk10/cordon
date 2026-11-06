"""Deterministic routing + narration for the copilot — the LLM-free path.

`match_question` maps the common question shapes (the UI's own suggested examples and
close paraphrases) straight to one of app.copilot.templates.TEMPLATE_REGISTRY's
whitelisted templates, so the copilot answers them with no LLM call at all. The LLM
router (app.copilot.llm.select_template) is only consulted for questions this returns
None for — it broadens coverage when available, it is never required for the basics.
Output goes through the exact same app.copilot.templates.execute_template whitelist +
extra="forbid" validation as an LLM selection; this module adds no new query surface.

`describe_result` turns an already-executed template's result into a plain-language
answer using only the figures in that result — the fallback whenever LLM narration is
unavailable or fails, so an answer never depends on the LLM either.

Deliberately conservative: anything ambiguous (two frameworks, two addresses, no clear
intent) returns None rather than guessing. Pure — no DB, no network — so it is directly
unit-testable.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta

# The copilot UI's suggested questions (frontend/src/components/copilot/CopilotView.tsx's
# empty state) — tests/integration/test_copilot_endpoint.py asserts each one returns a
# real answer with no LLM available. Keep the two in sync.
EXAMPLE_QUESTIONS: tuple[str, ...] = (
    "how many malicious emails this month",
    "how often was alice@example.com targeted",
    "what's our MITRE coverage",
)

_EMAIL_RE = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
# Indicator ids are UPPER_SNAKE_CASE (CREDENTIAL_REQUEST, AUTH_SPF_FAIL, ...); requiring
# an underscore keeps plain acronyms like MITRE/NIST from matching.
_INDICATOR_ID_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+\b")

_FRAMEWORK_PATTERNS: dict[str, re.Pattern[str]] = {
    "mitre": re.compile(r"\bmitre\b|\batt&ck\b"),
    "nist": re.compile(r"\bnist\b|\bcsf\b"),
    "iso": re.compile(r"\biso\b|\b27001\b"),
    "soc2": re.compile(r"\bsoc ?2\b"),
}
_COVERAGE_RE = re.compile(r"\bcover|\bcontrols?\b|\bcomplian|\bgaps?\b|\bposture\b")
_TARGET_RE = re.compile(r"\btarget|\bhit\b|\battack|\bphish|\breceiv|\bhow often\b|\btimes\b")
_TOP_RE = re.compile(r"\btop\b|\bmost (?:common|frequent|triggered|seen)\b|\bleading\b")
_TOP_SUBJECT_RE = re.compile(r"\bindicators?\b|\bsignals?\b|\bthreats?\b|\bfindings?\b|\breasons?\b")
_TOP_N_RE = re.compile(r"\btop (\d{1,2})\b")
_COUNT_RE = re.compile(r"\bhow many\b|\bcount\b|\bnumber of\b|\btotal\b|\bbreakdown\b|\bhow much\b")
_VERDICT_SUBJECT_RE = re.compile(
    r"\bmalicious\b|\bsuspicious\b|\bsafe\b|\bphish|\bthreats?\b|\bverdicts?\b|\bemails?\b"
    r"|\bmessages?\b|\bcases?\b|\bdetections?\b"
)
# A count/top question with an extra condition ("...had credential requests", "...from
# paypal", "...with attachments") asks something narrower than a plain verdict count or
# indicator ranking; answering it with one would be a confident wrong answer, so those
# are left to the LLM router (or the "rephrase" response) instead.
_QUALIFIER_RE = re.compile(
    r"\b(?:with|had|contain(?:s|ing)?|triggered|triggering|about|from|by|mentioning"
    r"|involving|targeting|sent to|that|which|where|whose)\b"
)
_LAST_N_DAYS_RE = re.compile(r"\b(?:last|past|previous) (\d{1,3}) days?\b")


def _normalize(question: str) -> str:
    return " ".join(question.lower().replace("’", "'").split())


def _month_start(value: datetime) -> datetime:
    return value.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def _date_range(text: str, now: datetime) -> dict:
    """Resolves a relative time phrase to {date_from, date_to} (naive UTC, matching how
    Case.created_at is compared everywhere else). No phrase -> {} (all time)."""
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    just_before = timedelta(microseconds=1)  # templates filter created_at <= date_to

    if match := _LAST_N_DAYS_RE.search(text):
        return {"date_from": now - timedelta(days=int(match.group(1)))}
    if re.search(r"\btoday\b", text):
        return {"date_from": day_start}
    if re.search(r"\byesterday\b", text):
        return {"date_from": day_start - timedelta(days=1), "date_to": day_start - just_before}
    if re.search(r"\b(?:last|past) 24 hours\b", text):
        return {"date_from": now - timedelta(hours=24)}
    week_start = day_start - timedelta(days=day_start.weekday())
    if re.search(r"\bthis week\b", text):
        return {"date_from": week_start}
    if re.search(r"\blast week\b", text):
        return {"date_from": week_start - timedelta(days=7), "date_to": week_start - just_before}
    month_start = _month_start(now)
    if re.search(r"\bthis month\b", text):
        return {"date_from": month_start}
    if re.search(r"\blast month\b", text):
        return {
            "date_from": _month_start(month_start - just_before),
            "date_to": month_start - just_before,
        }
    if re.search(r"\bthis quarter\b", text):
        return {"date_from": month_start.replace(month=3 * ((now.month - 1) // 3) + 1)}
    if re.search(r"\bthis year\b", text):
        return {"date_from": month_start.replace(month=1)}
    return {}


def match_question(question: str, now: datetime) -> tuple[str, dict] | None:
    """Returns (template_name, raw_params) for a recognized question shape, else None.
    `now` is naive UTC; it anchors phrases like "this month"."""
    text = _normalize(question)
    dates = _date_range(text, now)

    emails = set(_EMAIL_RE.findall(text))
    if emails:
        if len(emails) == 1 and _TARGET_RE.search(text):
            return "target_lookup", {"recipient": emails.pop(), **dates}
        return None

    frameworks = [key for key, pattern in _FRAMEWORK_PATTERNS.items() if pattern.search(text)]
    if frameworks:
        if len(frameworks) == 1 and _COVERAGE_RE.search(text):
            return "framework_coverage", {"framework": frameworks[0], **dates}
        return None

    indicator_ids = set(_INDICATOR_ID_RE.findall(question))
    if indicator_ids:
        if len(indicator_ids) == 1:
            return "indicator_case_count", {"indicator_id": indicator_ids.pop(), **dates}
        return None

    if _QUALIFIER_RE.search(text):
        return None

    if _TOP_RE.search(text) and _TOP_SUBJECT_RE.search(text):
        params: dict = dict(dates)
        if match := _TOP_N_RE.search(text):
            params["top_n"] = max(1, min(20, int(match.group(1))))
        return "top_indicators", params

    if _COUNT_RE.search(text) and _VERDICT_SUBJECT_RE.search(text):
        return "verdict_counts", dates

    return None


def _period(result: dict) -> str:
    date_from, date_to = result.get("date_from"), result.get("date_to")
    if date_from and date_to:
        return f" between {date_from[:10]} and {date_to[:10]}"
    if date_from:
        return f" since {date_from[:10]}"
    if date_to:
        return f" up to {date_to[:10]}"
    return ""


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" if n == 1 else f"{n} {word}s"


def describe_result(template_name: str, result: dict) -> str:
    """A plain-language answer built only from `result`'s own figures."""
    period = _period(result)

    if template_name == "verdict_counts":
        counts = result.get("counts", {})
        total = result.get("total", 0)
        if not total:
            return f"No emails were analyzed{period or ' yet'}."
        return (
            f"Cordon analyzed {_plural(total, 'email')}{period}: "
            f"{counts.get('malicious', 0)} malicious, {counts.get('suspicious', 0)} "
            f"suspicious, and {counts.get('safe', 0)} safe."
        )

    if template_name == "framework_coverage":
        if result.get("error"):
            return f"Coverage for {result.get('framework', 'that framework')} isn't available: {result['error']}"
        return (
            f"{result['framework_name']}: {result['operating_controls']} of "
            f"{result['total_controls']} mapped controls ({result['coverage_pct']:g}%) have at "
            f"least one supporting detection{period}."
        )

    if template_name == "target_lookup":
        recipient = result.get("recipient")
        hits = result.get("hit_count", 0)
        if not hits:
            return f"{recipient} has not been targeted by any suspicious or malicious email{period}."
        answer = f"{recipient} was targeted by {_plural(hits, 'suspicious or malicious email')}{period}."
        if result.get("top_indicator_title"):
            answer += f" Most common indicator: {result['top_indicator_title']}."
        if result.get("flagged_for_training"):
            answer += " They are flagged for micro-training."
        return answer

    if template_name == "top_indicators":
        top = result.get("top_indicators", [])
        if not top:
            return f"No indicators were triggered{period}."
        listed = "; ".join(f"{item['title']} ({item['count']})" for item in top)
        return f"Most frequently triggered indicators{period}: {listed}."

    if template_name == "indicator_case_count":
        count = result.get("count", 0)
        return f"{_plural(count, 'case')} triggered {result.get('indicator_id')}{period}."

    if template_name == "unsupported_question":
        return f"That can't be answered from Cordon's data: {result.get('reason', '')}".strip()

    return "Here are the figures retrieved for your question."
