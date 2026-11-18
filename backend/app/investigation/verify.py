"""Grounding verification for the investigation agent's report (M10 Stage 2). Pure: no DB,
no network.

Two layers, both fail closed:

1. Whole-response checks (reject => the rules-only report is used instead):
   strict schema (extra="forbid", fixed enums), stated_verdict must equal Cordon's verdict,
   and every cited evidence id must be one the model was actually shown. Same contract as
   app.investigation.llm_summary and app.assistant.llm: a single fabricated citation
   discards everything rather than being quietly filtered.
2. Per-claim checks (drop the claim, count it): a claim must cite at least one id, and every
   concrete token it states (IP address, email address, domain, number) must appear in the
   text of the evidence it cites. That is what catches "the sender is in Russia (EV2)" when
   EV2 never mentions Russia's IP, or an invented "14 other recipients". If more than half
   the claims fail, the narrative as a whole is untrustworthy and is rejected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.investigation.assessment import HYPOTHESES

Verdict = Literal["safe", "suspicious", "malicious"]

_EV_REF_RE = re.compile(r"\(?\bEV\d+\b\)?", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE)
_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
# Words that look like domains to the regex but are ordinary prose.
_PROSE_DOTTED = frozenset({"e.g", "i.e", "etc"})


class ClaimPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    text: str = Field(min_length=1, max_length=600)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)


class HypothesisPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: Literal[HYPOTHESES]  # type: ignore[valid-type]
    rationale: str = Field(min_length=1, max_length=600)
    evidence_ids: list[str] = Field(default_factory=list, max_length=20)
    uncertainty: Literal["low", "medium", "high"]


class SubmissionPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stated_verdict: Verdict
    claims: list[ClaimPayload] = Field(min_length=1, max_length=10)
    hypothesis: HypothesisPayload


@dataclass
class VerificationResult:
    accepted: bool
    reason: str | None = None
    claims: list[dict] = field(default_factory=list)
    removed: list[dict] = field(default_factory=list)
    hypothesis: dict | None = None
    hypothesis_rejected: bool = False


def concrete_tokens(text: str) -> set[str]:
    """IPs, email addresses, domains and numbers stated in `text` (EV references removed)."""
    text = _EV_REF_RE.sub(" ", text)
    tokens: set[str] = set()
    for m in _EMAIL_RE.findall(text):
        tokens.add(m.lower())
    stripped = _EMAIL_RE.sub(" ", text)
    for m in _IP_RE.findall(stripped):
        tokens.add(m.lower())
    stripped = _IP_RE.sub(" ", stripped)
    for m in _DOMAIN_RE.findall(stripped):
        if m.lower() not in _PROSE_DOTTED:
            tokens.add(m.lower())
    stripped = _DOMAIN_RE.sub(" ", stripped)
    for m in _NUMBER_RE.findall(stripped):
        tokens.add(m)
    return tokens


def _unsupported_tokens(text: str, cited: list[str], evidence_text: dict[str, str]) -> set[str]:
    corpus = " ".join(evidence_text.get(eid, "") for eid in cited).lower()
    return {t for t in concrete_tokens(text) if t not in corpus}


def verify_submission(
    raw: dict,
    *,
    cordon_verdict: str,
    shown_ids: set[str],
    evidence_text: dict[str, str],
) -> VerificationResult:
    try:
        payload = SubmissionPayload.model_validate(raw)
    except Exception as exc:  # noqa: BLE001
        return VerificationResult(accepted=False, reason=f"schema: {type(exc).__name__}")

    if payload.stated_verdict != cordon_verdict:
        return VerificationResult(accepted=False, reason="stated_verdict does not match Cordon's verdict")

    cited_all = {eid for c in payload.claims for eid in c.evidence_ids} | set(payload.hypothesis.evidence_ids)
    unknown = cited_all - shown_ids
    if unknown:
        return VerificationResult(accepted=False, reason=f"cited evidence never shown: {sorted(unknown)}")

    kept: list[dict] = []
    removed: list[dict] = []
    for claim in payload.claims:
        text = claim.text.strip()
        if not claim.evidence_ids:
            removed.append({"text": text, "reason": "no evidence cited"})
            continue
        missing = _unsupported_tokens(text, claim.evidence_ids, evidence_text)
        if missing:
            removed.append({"text": text, "reason": "not in cited evidence: " + ", ".join(sorted(missing))})
            continue
        kept.append({"text": text, "evidence_ids": list(dict.fromkeys(claim.evidence_ids))})

    if not kept or len(removed) > len(payload.claims) / 2:
        return VerificationResult(
            accepted=False, reason="most claims were unsupported by the evidence", removed=removed
        )

    hyp = payload.hypothesis
    hypothesis = None
    hypothesis_rejected = False
    if hyp.evidence_ids and not _unsupported_tokens(hyp.rationale, hyp.evidence_ids, evidence_text):
        hypothesis = {
            "category": hyp.category,
            "rationale": hyp.rationale.strip(),
            "evidence_ids": list(dict.fromkeys(hyp.evidence_ids)),
            "uncertainty": hyp.uncertainty,
        }
    else:
        hypothesis_rejected = True

    return VerificationResult(
        accepted=True,
        claims=kept,
        removed=removed,
        hypothesis=hypothesis,
        hypothesis_rejected=hypothesis_rejected,
    )
