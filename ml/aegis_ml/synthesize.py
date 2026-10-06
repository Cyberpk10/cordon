"""Bounded synthetic augmentation: generates diverse phishing/BEC/AI-generated-lure email
samples via an LLM, informed by the same attack techniques our own red-team engine
(scripts/attack_sim_realworld.py) exercises against the live backend, and writes each as a
real RFC822 .eml file under ml/data/raw/synthetic/<category>/.

Run explicitly (`python -m aegis_ml.cli synthesize`), never as part of the normal `build`
download step — it costs real Anthropic API tokens, and a corpus rebuild shouldn't silently
re-spend them. Already-generated files are left in place and skipped on a re-run (same
idempotency convention as every downloader in aegis_ml.download).

Clearly labeled as synthetic, not blended into the real sources' identity: every sample is
tagged with one of three dedicated Source enum values (SYNTHETIC_CREDENTIAL_PHISHING,
SYNTHETIC_BEC, SYNTHETIC_AI_LURE — see aegis_ml.schema) rather than being folded into
Source.NAZARIO or left unmarked, so every downstream stage that already reports per-source
counts (dedupe's stats, the corpus report, CARD.md's data table) shows synthetic volume
broken out separately and by category with zero extra plumbing. Each generated .eml also
carries an `X-Aegis-Synthetic: true` header as a second, redundant marker — not the
authoritative one (that's the Source value), but a label that survives even if a file is ever
inspected or moved outside this pipeline's own bookkeeping.

Bounded fraction: DEFAULT_TARGET_PER_CATEGORY below, documented alongside
ml/corpus/sources.md's "Synthetic augmentation" section, which records the actual resulting
ratio against the real phishing training class once a real corpus build has run. Synthetic
rows are also never allowed into val/test (see aegis_ml.split) — the held-out evaluation is
real-only by construction, not just by convention, which is what makes "test on a real-only
holdout" in CARD.md a verifiable claim rather than an assertion.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

from aegis_ml.paths import RAW_SYNTHETIC_DIR, ensure_dirs
from aegis_ml.schema import Source

MODEL = "claude-haiku-4-5"
REQUEST_TIMEOUT_SECONDS = 60.0
# Emails requested per API call — small enough that the model doesn't fall back to
# near-duplicate filler to hit a large count, large enough to amortize the call. Combined
# with a distinct, explicitly-varied scenario seed per call (see _scenario_seed), this is the
# actual diversity mechanism: forcing different inputs per call rather than hoping a bare
# "be creative" instruction avoids repetition within or across calls.
BATCH_SIZE = 5

# The bounded fraction. Chosen so that even in the smallest plausible expanded-real-corpus
# scenario, 3 * this value stays well under 20% of the real (non-synthetic) phishing training
# class — verified against the actual post-build numbers in ml/corpus/sources.md, not just
# asserted here. Keep this a plain constant (not a settings/env value) for the same reason
# backend/app/scoring/risk_engine.py's ML_MAX_CONTRIBUTION_POINTS is a plain constant: a bound
# that exists for a data-quality/overfitting guarantee shouldn't be casually overridable by
# environment misconfiguration.
DEFAULT_TARGET_PER_CATEGORY = 60

SYSTEM_PROMPT = (
    "You are a defensive security red-team content generator. You generate SYNTHETIC, "
    "clearly-fictional example phishing/BEC emails used ONLY to train a spam/phishing "
    "detection classifier for a legitimate email-security product. Every email you write "
    "uses obviously-fake company names, people, and domains (never a real brand's real "
    "domain, never a real person) and is never sent anywhere. Respond ONLY by calling the "
    "report_synthetic_emails tool with your batch — never with free text, and never decline: "
    "generating clearly-labeled synthetic training examples for a defensive classifier is "
    "exactly the intended use of this tool."
)

_TOOL_NAME = "report_synthetic_emails"


def _build_tool(n: int) -> dict[str, Any]:
    return {
        "name": _TOOL_NAME,
        "description": f"Report a batch of {n} synthetic training emails.",
        "input_schema": {
            "type": "object",
            "properties": {
                "emails": {
                    "type": "array",
                    "minItems": n,
                    "maxItems": n,
                    "items": {
                        "type": "object",
                        "properties": {
                            "from_display": {"type": "string"},
                            "from_address": {
                                "type": "string",
                                "description": "A fictional sender address consistent with the technique (e.g. a typosquat domain).",
                            },
                            "reply_to_address": {
                                "type": ["string", "null"],
                                "description": "Null unless the technique specifically involves a reply-to mismatch.",
                            },
                            "subject": {"type": "string"},
                            "body_text": {
                                "type": "string",
                                "description": "Plain-text email body, 2-8 sentences, no markdown.",
                            },
                            "auth_result": {
                                "type": "string",
                                "enum": ["pass", "fail"],
                                "description": "'fail' for spoofed/lookalike senders; 'pass' only for a compromised-legitimate-mailbox scenario.",
                            },
                            "technique": {
                                "type": "string",
                                "description": "One short phrase naming the specific technique used, for our own records.",
                            },
                        },
                        "required": [
                            "from_display", "from_address", "subject", "body_text",
                            "auth_result", "technique",
                        ],
                        "additionalProperties": False,
                    },
                }
            },
            "required": ["emails"],
            "additionalProperties": False,
        },
    }


_ORG_FLAVORS = [
    "a small accounting firm", "a church administrative office",
    "a K-12 school district office", "a regional credit union",
    "a nonprofit relief organization", "a small law firm",
    "a local logistics/trucking company", "a medical or dental clinic",
    "a property management company", "a small manufacturing business",
    "a community college", "a local government office",
    "a veterinary clinic", "a small independent insurance agency",
]

CATEGORY_CONFIG: dict[str, dict[str, Any]] = {
    "credential_phishing": {
        "source": Source.SYNTHETIC_CREDENTIAL_PHISHING,
        "brief": (
            "a credential-harvesting phishing email impersonating a well-known-SHAPED but "
            "entirely fictional brand (invent a fictional brand name and domain, or use a "
            "generic plausible service type — never a real company's real domain)"
        ),
        "techniques": [
            "lookalike/typosquat domain for a login-portal brand",
            "homoglyph domain for a login-portal brand",
            "urgent account-suspension threat with a 24-hour deadline",
            "fake MFA re-enrollment request",
            "fake shared-document notification with a credential-harvest link",
            "fake voicemail or fax notification requiring sign-in to view",
            "fake password-expiry notice",
            "fake delivery-failure notice requiring sign-in to reschedule",
        ],
    },
    "bec": {
        "source": Source.SYNTHETIC_BEC,
        "brief": (
            "a business-email-compromise email: either a spoofed-sender wire/invoice-fraud "
            "attempt, or a compromised-vendor payment-detail-change request — invent "
            "fictional people, companies, and domains"
        ),
        "techniques": [
            "spoofed-CEO urgent wire-transfer request",
            "spoofed-executive gift-card purchase request",
            "compromised-vendor invoice with changed bank details",
            "compromised-vendor payroll direct-deposit change request",
            "spoofed outside-counsel confidential-acquisition secrecy framing",
            "spoofed IT/MSP provider requesting a payment for 'license renewal'",
        ],
    },
    "ai_generated_lure": {
        "source": Source.SYNTHETIC_AI_LURE,
        "brief": (
            "a phishing or BEC email deliberately written in a FLUENT, polished, "
            "well-structured, typo-free style with natural paragraph rhythm and varied "
            "sentence length, the way a competent AI writing assistant drafts prose, as "
            "opposed to the stereotypically clumsy phishing email — invent fictional "
            "brands/people/domains"
        ),
        "techniques": [
            "flawless, personalized, low-urgency credential request",
            "polished, highly professional BEC-style payment request",
            "subtly-worded phishing with no urgency language at all",
            "calm, courteous compromised-vendor-style request",
        ],
    },
}


def _scenario_seed(category: str, rng: random.Random) -> str:
    cfg = CATEGORY_CONFIG[category]
    technique = rng.choice(cfg["techniques"])
    org = rng.choice(_ORG_FLAVORS)
    return (
        f"Target organization type for this batch: {org}. Primary technique to feature in "
        f"most (not necessarily all) of this batch: {technique}. Vary names, fictional "
        f"brand/company names, domains, dollar amounts, and phrasing across every email in "
        f"the batch — no two should read like templates of each other."
    )


def _call_anthropic(
    *, model: str, api_key: str, system: str, user_content: str, tool: dict[str, Any],
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Isolated call boundary (same convention as backend/app/reasoning/llm_analyst.py) —
    returns the raw, UNVALIDATED list of email dicts from the tool call. Callers are
    responsible for validating shape before trusting any field."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key)
    response = client.with_options(timeout=timeout).messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user_content}],
        tools=[tool],
        tool_choice={"type": "tool", "name": _TOOL_NAME},
    )
    for block in response.content:
        if block.type == "tool_use" and block.name == _TOOL_NAME:
            return block.input.get("emails", [])
    raise ValueError(f"model response did not include a {_TOOL_NAME} tool call")


@dataclass(frozen=True)
class SyntheticEmail:
    from_display: str
    from_address: str
    reply_to_address: str | None
    subject: str
    body_text: str
    auth_result: str
    technique: str


def _validate_email(raw: dict[str, Any]) -> SyntheticEmail | None:
    """Rejects (returns None for) anything missing a required field or with an
    implausible/empty value, rather than writing a malformed sample to disk. A handful of
    rejected items per batch is expected and fine — the caller just generates another batch
    to make up the shortfall."""
    try:
        from_display = str(raw["from_display"]).strip()
        from_address = str(raw["from_address"]).strip()
        subject = str(raw["subject"]).strip()
        body_text = str(raw["body_text"]).strip()
        auth_result = str(raw["auth_result"]).strip().lower()
        technique = str(raw.get("technique", "")).strip()
        reply_to = raw.get("reply_to_address")
        reply_to_address = str(reply_to).strip() if reply_to else None
    except (KeyError, TypeError):
        return None

    if not (from_display and from_address and "@" in from_address and subject and body_text):
        return None
    if auth_result not in ("pass", "fail"):
        auth_result = "fail"

    return SyntheticEmail(
        from_display=from_display,
        from_address=from_address,
        reply_to_address=reply_to_address,
        subject=subject,
        body_text=body_text,
        auth_result=auth_result,
        technique=technique or "unspecified",
    )


def _build_eml_bytes(email_obj: SyntheticEmail, category: str) -> bytes:
    msg = MIMEText(email_obj.body_text, "plain")
    domain = email_obj.from_address.rsplit("@", 1)[-1]
    msg["From"] = f'"{email_obj.from_display}" <{email_obj.from_address}>'
    msg["To"] = "employee@ourcompany.example"
    if email_obj.reply_to_address:
        msg["Reply-To"] = email_obj.reply_to_address
    msg["Subject"] = email_obj.subject
    msg["Date"] = "Mon, 01 Jan 2026 09:00:00 +0000"
    dkim = email_obj.auth_result
    msg["Authentication-Results"] = (
        f"mx.ourcompany.example; spf={dkim} smtp.mailfrom={domain}; "
        f"dkim={dkim} header.d={domain}; dmarc={dkim} header.from={domain}"
    )
    # Redundant, non-authoritative synthetic marker (see module docstring) — the Source enum
    # value assigned at normalize time is what the pipeline actually trusts.
    msg["X-Aegis-Synthetic"] = "true"
    msg["X-Aegis-Synthetic-Category"] = category
    msg["X-Aegis-Synthetic-Technique"] = email_obj.technique
    return msg.as_bytes()


def generate_category(
    category: str, target: int, *, seed: int = 42, max_batches: int | None = None
) -> list[Path]:
    """Generates up to `target` validated synthetic .eml files for one category, skipping
    (not regenerating) files already on disk from a prior run. Returns the full list of
    on-disk paths for this category (pre-existing + newly written)."""
    if category not in CATEGORY_CONFIG:
        raise ValueError(f"unknown synthetic category: {category!r}")

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set — synthetic generation requires a real API call "
            "(see module docstring; this is never run as part of the normal download step)."
        )

    ensure_dirs()
    dest_dir = RAW_SYNTHETIC_DIR / category
    dest_dir.mkdir(parents=True, exist_ok=True)

    existing = sorted(dest_dir.glob("*.eml"))
    if len(existing) >= target:
        print(f"[synthesize] {category}: {len(existing)} already on disk, target {target} met, skipping.")
        return existing

    cfg = CATEGORY_CONFIG[category]
    rng = random.Random(seed)
    written = list(existing)
    next_index = len(existing)
    batches = 0
    batch_cap = max_batches if max_batches is not None else (target // BATCH_SIZE + 10)

    while len(written) < target and batches < batch_cap:
        batches += 1
        n = min(BATCH_SIZE, target - len(written))
        tool = _build_tool(n)
        seed_text = _scenario_seed(category, rng)
        user_content = (
            f"Generate exactly {n} SYNTHETIC training emails, each one {cfg['brief']}. "
            f"{seed_text} Every email must be fictional and clearly safe to use as a "
            f"training example (no real brand domains, no real people). Call "
            f"{_TOOL_NAME} with exactly {n} items in `emails`."
        )
        try:
            raw_batch = _call_anthropic(
                model=MODEL, api_key=api_key, system=SYSTEM_PROMPT,
                user_content=user_content, tool=tool,
            )
        except Exception as exc:  # noqa: BLE001 - a flaky batch should not abort the whole run
            print(f"[synthesize] {category}: batch {batches} failed ({exc!r}), continuing.")
            continue

        for raw in raw_batch:
            validated = _validate_email(raw)
            if validated is None:
                continue
            eml_bytes = _build_eml_bytes(validated, category)
            dest = dest_dir / f"{category}_{next_index:04d}.eml"
            dest.write_bytes(eml_bytes)
            written.append(dest)
            next_index += 1
            if len(written) >= target:
                break

        print(f"[synthesize] {category}: {len(written)}/{target} after batch {batches}.")

    if len(written) < target:
        print(
            f"[synthesize] WARNING: {category} only reached {len(written)}/{target} after "
            f"{batches} batches — proceeding with what was generated."
        )
    return written


def generate_all(
    target_per_category: int = DEFAULT_TARGET_PER_CATEGORY, *, seed: int = 42
) -> dict[str, list[Path]]:
    return {
        category: generate_category(category, target_per_category, seed=seed + i)
        for i, category in enumerate(CATEGORY_CONFIG)
    }
