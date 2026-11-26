"""Deterministic verdict-level assessment for an investigation (M10 Stage 2). Pure: no DB.

Confidence, campaign, blast radius, the recommended action and its suggested autonomy tier
are all computed here from evidence Cordon's engines produced. The LLM never sets them, the
same "bounded signal" principle as the risk engine: a prompt-injected or confused model can
change the wording of a narrative, never what Cordon recommends or how sure it is.

Recommend-only. Nothing here (or anything that imports it) executes an action; the
suggested tier is what app.autonomy.policy would need before this action could ever run
automatically, recorded so auto-containment can be wired later.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from app.autonomy.actions import (
    ACTIONS,
    BLOCK_SENDER_DOMAIN,
    FINDING_ACTION_MAP,
    FLAG_ACCOUNT_FOR_REVIEW,
    QUARANTINE_EMAIL,
)
from app.core.config import settings
from app.investigation.aggregation import THREAT_INTEL_EMAIL_INDICATOR_IDS

LOW_CONFIDENCE_NOTE = "Limited evidence: treat this as a lead to check, not a conclusion."

# Independent signal families. Several indicators from one family count once.
_FAMILIES: dict[str, frozenset[str]] = {
    "threat_intel": THREAT_INTEL_EMAIL_INDICATOR_IDS,
    "authentication": frozenset({"AUTH_SPF_FAIL", "AUTH_DKIM_FAIL", "AUTH_DMARC_FAIL"}),
    "impersonation": frozenset({
        "LOOKALIKE_DOMAIN", "LOOKALIKE_OF_KNOWN_SENDER", "PUNYCODE_IDN_DOMAIN",
        "DISPLAY_NAME_EMAIL_MISMATCH", "IMPERSONATED_DISPLAY_NAME", "SENDER_REPLYTO_MISMATCH",
        "DOMAIN_LOOKS_RANDOMLY_GENERATED",
    }),
    "links": frozenset({
        "LINK_DISPLAY_HREF_MISMATCH", "LINK_SHORTENER", "LINK_SUSPICIOUS_TLD", "LINK_IP_LITERAL",
        "SUSPICIOUS_LINK_PUBLIC_CHANNEL", "EXTERNAL_DM_WITH_LINK",
    }),
    "attachment": frozenset({
        "ATTACHMENT_RISKY_EXTENSION", "ATTACHMENT_DOUBLE_EXTENSION", "ATTACHMENT_MACRO_ENABLED",
        "ATTACHMENT_HTML", "ATTACHMENT_ARCHIVE_RISKY_CONTENT", "ATTACHMENT_ENCRYPTED_ARCHIVE",
        "ATTACHMENT_TYPE_MISMATCH",
    }),
    "sensitive_ask": frozenset({"CREDENTIAL_REQUEST", "PAYMENT_REQUEST", "UNKNOWN_VENDOR_CLAIM", "TRUSTED_SENDER_ANOMALY"}),
    # AUTHENTICATED_SENDER_CONTENT_MISMATCH: real institutional mail carrying a lure, i.e. a
    # hijacked mailbox.
    "account_takeover": frozenset({"ACCOUNT_TAKEOVER", "ACCOUNT_TAKEOVER_LATERAL", "AUTHENTICATED_SENDER_CONTENT_MISMATCH"}),
    "evasion": frozenset({"HIDDEN_AI_INSTRUCTION_PAYLOAD"}),
}
# Present but weak on their own: they never raise confidence by themselves.
# LURE_COMBINATION only restates findings already counted in their own families.
_WEAK = frozenset({
    "FIRST_CONTACT_SENDER", "URGENCY_LANGUAGE", "AI_AUTHORED_SUSPECTED",
    "SOCIAL_ENGINEERING_THEME", "LURE_COMBINATION",
})

_FAMILY_LABEL = {
    "threat_intel": "a threat-intelligence match",
    "authentication": "failed sender authentication",
    "impersonation": "sender impersonation",
    "links": "risky links",
    "attachment": "a risky attachment",
    "sensitive_ask": "a request for credentials or money",
    "account_takeover": "account-takeover behaviour",
    "evasion": "hidden instructions aimed at AI tools",
    "campaign": "a matching campaign hitting other recipients",
}

CONFIDENCE_SCORE = {"high": 0.85, "medium": 0.65, "low": 0.4}

HYPOTHESES = (
    "credential_phishing", "bec_payment_fraud", "account_takeover", "malware_delivery",
    "scam", "benign", "unclear",
)
HYPOTHESIS_LABEL = {
    "credential_phishing": "Credential phishing",
    "bec_payment_fraud": "Business email compromise / payment fraud",
    "account_takeover": "Compromised sender account",
    "malware_delivery": "Malware delivery",
    "scam": "Scam",
    "benign": "Legitimate mail",
    "unclear": "Unclear",
}


def families_hit(indicator_ids: list[str]) -> list[str]:
    ids = set(indicator_ids)
    return [name for name, members in _FAMILIES.items() if ids & members]


def assess_campaign(related: list[dict], case_recipients: list[str], now: datetime) -> dict:
    """one_off / possible_campaign / wave, from find_related_cases' output. Only links other
    than "same sender" count toward a wave: a regular correspondent's ten newsletters are
    not a campaign. A wave needs settings.investigation_wave_min_cases cases including this
    one, inside the wave window, across 2+ distinct recipients."""
    window_start = now - timedelta(days=settings.investigation_wave_window_days)
    linked = [
        r for r in related
        if any(not m.startswith("same sender") for m in r["match_reasons"])
    ]
    in_window = [r for r in linked if datetime.fromisoformat(r["created_at"]) >= window_start]
    recipients = {a.lower() for a in case_recipients}
    for r in in_window:
        recipients.update(a.lower() for a in r["to_addresses"])
    if len(in_window) + 1 >= settings.investigation_wave_min_cases and len(recipients) >= 2:
        status = "wave"
    elif linked or related:
        status = "possible_campaign" if linked else "one_off"
    else:
        status = "one_off"
    return {
        "status": status,
        "linked_case_ids": [r["id"] for r in linked],
        "cases_in_window": len(in_window) + 1,
        "recipients_in_window": len(recipients),
        "window_days": settings.investigation_wave_window_days,
    }


def assess_blast_radius(case_recipients: list[str], related: list[dict], scope: dict) -> dict:
    all_recipients = {a.lower() for a in case_recipients}
    exposed = set(all_recipients)
    for r in related:
        all_recipients.update(a.lower() for a in r["to_addresses"])
        if r["verdict"] != "safe":
            exposed.update(a.lower() for a in r["to_addresses"])
    return {
        "recipients": sorted(all_recipients),
        "exposed_recipients": sorted(exposed),
        "related_case_count": len(related),
        "possible_account_compromise": bool(scope.get("possible_account_compromise")),
        "compromise_signals": list(scope.get("compromise_signals") or []),
    }


def assess_confidence(
    verdict: str,
    indicator_ids: list[str],
    campaign: dict,
    evidence_available: bool,
    baseline_status: str | None,
) -> dict:
    """How sure Cordon is of its own verdict, and why. Counts independent families, not
    points, so ten weak signals can't masquerade as certainty."""
    fams = families_hit(indicator_ids)
    if campaign["status"] == "wave":
        fams = fams + ["campaign"]
    reasons: list[str] = []
    if verdict == "safe":
        strong_ids = [i for i in indicator_ids if i not in _WEAK]
        if not strong_ids and baseline_status == "established":
            level = "high"
            reasons.append("No findings, and the sender is an established correspondent.")
        elif not strong_ids:
            level = "medium" if baseline_status in (None, "first_contact") else "high"
            reasons.append("No findings of note." + (
                " The sender has no history with this account yet." if level == "medium" else ""
            ))
        else:
            level = "medium"
            reasons.append("Rated safe, but some findings were present below the suspicious threshold.")
    else:
        n = len(fams)
        if n >= 3 or (n >= 2 and ({"threat_intel", "account_takeover"} & set(fams))):
            level = "high"
        elif n == 2 or "threat_intel" in fams:
            level = "medium"
        else:
            level = "low"
        if fams:
            reasons.append(
                f"{n} independent signal famil{'y' if n == 1 else 'ies'}: "
                + ", ".join(_FAMILY_LABEL[f] for f in fams) + "."
            )
        else:
            reasons.append("Only weak signals (e.g. first contact or urgent wording) were found.")
    if not evidence_available:
        reasons.append("The raw email is no longer stored, so links and IPs could not be re-checked.")
        if level == "high":
            level = "medium"
    if level == "low":
        reasons.append(LOW_CONFIDENCE_NOTE)
    return {"level": level, "score": CONFIDENCE_SCORE[level], "reasons": reasons, "families": fams}


def rules_hypothesis(verdict: str, indicator_ids: list[str]) -> str:
    ids = set(indicator_ids)
    if verdict == "safe":
        return "benign"
    if ids & _FAMILIES["account_takeover"]:
        return "account_takeover"
    if ids & {"PAYMENT_REQUEST", "UNKNOWN_VENDOR_CLAIM"} or (
        "TRUSTED_SENDER_ANOMALY" in ids and "CREDENTIAL_REQUEST" not in ids
    ):
        return "bec_payment_fraud"
    if ids & _FAMILIES["attachment"]:
        return "malware_delivery"
    risky_links = ids & (_FAMILIES["links"] | {"LINK_KNOWN_MALICIOUS"})
    # A link whose visible text shows one site but goes to another is the classic credential
    # lure, as is a risky link from a sender that impersonates someone or fails authentication.
    if (
        "CREDENTIAL_REQUEST" in ids
        or "LINK_DISPLAY_HREF_MISMATCH" in ids
        or (risky_links and ids & (_FAMILIES["impersonation"] | _FAMILIES["authentication"]))
    ):
        return "credential_phishing"
    if ids & (_FAMILIES["links"] | _FAMILIES["impersonation"] | {"LINK_KNOWN_MALICIOUS"}):
        return "scam"
    return "unclear"


def recommend(
    verdict: str,
    indicator_ids: list[str],
    confidence: dict,
    campaign: dict,
    ato_kind: str | None,
    sender_classification: str | None,
    sender_domain: str | None,
) -> dict:
    """One primary action from the fixed autonomy catalog (or none), plus the tier
    app.autonomy.policy would require before it could ever run unattended. A known
    correspondent's domain is never suggested for blocking: when a real vendor's mailbox is
    taken over, blocking the vendor is the wrong response."""
    if verdict == "safe":
        return {
            "action": None,
            "title": "No action needed: keep monitoring",
            "suggested_tier": None,
            "secondary_actions": [],
            "applies_to_case_ids": [],
            "rationale": "Rated safe with no findings that call for a response.",
            "executed": False,
        }

    secondary: list[str] = []
    if ato_kind == "lateral":
        action = FLAG_ACCOUNT_FOR_REVIEW
        secondary = [QUARANTINE_EMAIL]
        rationale = (
            "The sender is a colleague whose mailbox looks compromised: review that account "
            "(sessions, mailbox rules, recent sign-ins) and pull the message."
        )
    elif ato_kind == "external":
        action = QUARANTINE_EMAIL
        rationale = (
            "A known external sender's account looks compromised: pull the message and verify "
            "any request with the sender through a channel you already trust."
        )
    else:
        mapped = {FINDING_ACTION_MAP[i] for i in indicator_ids if i in FINDING_ACTION_MAP}
        if (
            BLOCK_SENDER_DOMAIN in mapped
            and sender_classification != "established"
            and confidence["level"] == "high"
        ):
            action = BLOCK_SENDER_DOMAIN
            secondary = [QUARANTINE_EMAIL]
            rationale = f"Unknown sender domain {sender_domain or ''} with high-confidence impersonation or authentication failures.".replace("  ", " ")
        else:
            action = QUARANTINE_EMAIL
            rationale = "Pull the message from the inbox while it is reviewed."

    definition = ACTIONS[action]
    if confidence["level"] == "low" or confidence["score"] < definition.min_confidence_floor:
        tier = "L0"
    else:
        tier = "L2" if definition.containment else "L1"
    applies = [] if campaign["status"] != "wave" else list(campaign["linked_case_ids"])
    if applies:
        rationale += f" This is part of a wave: apply the same response to the {len(applies)} linked message(s)."
    return {
        "action": action,
        "title": definition.title,
        "suggested_tier": tier,
        "secondary_actions": [ACTIONS[a].title for a in secondary],
        "applies_to_case_ids": applies,
        "rationale": rationale,
        "executed": False,
    }
