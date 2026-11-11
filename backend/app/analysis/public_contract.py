"""The stable, flattened /v1/analyze/email response contract for external clients (the Gmail
add-on, scripts). Pure: no DB, no network, no detection logic. It only reshapes a result the
shared pipeline (app.analysis.email_pipeline) already produced, so the add-on shows exactly
what the web app would, with nothing added.

Mapping rules (pinned by tests/unit/test_public_contract.py):
- verdict: Cordon's "safe" is published as "clean"; "suspicious"/"malicious" unchanged.
- category: the LLM analyst's intent category when an assessment was obtained, otherwise the
  category of the highest-scoring indicator (e.g. "link", "sender"), otherwise "none".
- summary: one deterministic sentence built from the verdict, score and indicator titles.
  Never LLM text, so it can't drift from the findings it summarizes.
- top_indicators: titles of the (up to) three highest-scoring indicators.
- auth: SPF/DKIM/DMARC collapsed to pass | fail | none. softfail and permerror count as
  fail (the domain did not authorize the message); neutral, temperror and a missing result
  count as none (no usable verdict either way).
- frameworks: "<short framework name> <control id>", MITRE first, de-duplicated.
"""

from __future__ import annotations

from typing import Iterable, Literal

from app.models.schemas import AuthResults, AuthResultValue, FrameworkControlRef, Indicator, Verdict

PublicVerdict = Literal["malicious", "suspicious", "clean"]
PublicAuth = Literal["pass", "fail", "none"]

TOP_INDICATOR_COUNT = 3

_VERDICT: dict[Verdict, PublicVerdict] = {
    Verdict.MALICIOUS: "malicious",
    Verdict.SUSPICIOUS: "suspicious",
    Verdict.SAFE: "clean",
}

_AUTH: dict[AuthResultValue, PublicAuth] = {
    AuthResultValue.PASS: "pass",
    AuthResultValue.FAIL: "fail",
    AuthResultValue.SOFTFAIL: "fail",
    AuthResultValue.PERMERROR: "fail",
    AuthResultValue.NEUTRAL: "none",
    AuthResultValue.TEMPERROR: "none",
    AuthResultValue.NONE: "none",
    AuthResultValue.UNKNOWN: "none",
}

# Display order and short labels for the four loaded frameworks (app/mapping/frameworks/).
_FRAMEWORK_LABELS: tuple[tuple[str, str], ...] = (
    ("mitre_attack", "MITRE"),
    ("nist_csf", "NIST"),
    ("iso_27001", "ISO"),
    ("soc2", "SOC 2"),
)


def public_verdict(verdict: Verdict) -> PublicVerdict:
    return _VERDICT[verdict]


def public_auth(auth: AuthResults) -> dict[str, PublicAuth]:
    return {"spf": _AUTH[auth.spf], "dkim": _AUTH[auth.dkim], "dmarc": _AUTH[auth.dmarc]}


def ranked_indicators(indicators: Iterable[Indicator]) -> list[Indicator]:
    """Highest score first; ties keep the engine's own order (sorted() is stable)."""
    return sorted(indicators, key=lambda i: i.score, reverse=True)


def category_for(indicators: list[Indicator], llm_intent_category: str | None) -> str:
    if llm_intent_category:
        return llm_intent_category
    ranked = ranked_indicators(indicators)
    return ranked[0].category if ranked else "none"


def summary_sentence(verdict: Verdict, score: int, indicators: list[Indicator]) -> str:
    ranked = ranked_indicators(indicators)
    label = public_verdict(verdict).capitalize()
    if not ranked:
        return f"{label} ({score}/100): Cordon found no phishing indicators in this email."
    count = len(ranked)
    findings = f"{count} finding" + ("" if count == 1 else "s")
    lead = ranked[0].title
    if verdict is Verdict.SAFE:
        return f"{label} ({score}/100): {findings}, not enough to flag this email (strongest: {lead})."
    return f"{label} ({score}/100): {findings}, the strongest being: {lead}."


def framework_tags(framework_mappings: dict[str, list[FrameworkControlRef]]) -> list[str]:
    tags: list[str] = []
    seen: set[str] = set()
    for key, label in _FRAMEWORK_LABELS:
        for ref in framework_mappings.get(key, []):
            tag = f"{label} {ref.control_id}"
            if tag not in seen:
                seen.add(tag)
                tags.append(tag)
    return tags


def build_public_result(
    *,
    verdict: Verdict,
    score: int,
    indicators: list[Indicator],
    framework_mappings: dict[str, list[FrameworkControlRef]],
    auth_results: AuthResults,
    llm_intent_category: str | None,
) -> dict:
    return {
        "verdict": public_verdict(verdict),
        "score": score,
        "category": category_for(indicators, llm_intent_category),
        "summary": summary_sentence(verdict, score, indicators),
        "top_indicators": [i.title for i in ranked_indicators(indicators)[:TOP_INDICATOR_COUNT]],
        "auth": public_auth(auth_results),
        "frameworks": framework_tags(framework_mappings),
    }
