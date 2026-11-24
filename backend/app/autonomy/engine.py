"""Graduated-autonomy decision engine (D5). Pure: no DB, no I/O, no clock.

Takes the deterministic outputs Cordon already computed for a case (the verdict, and D4's
confidence, campaign and recommendation from app.investigation.assessment) plus the account's
policy, and returns every action the rules call for, each with exactly one outcome:

    performed          do it now (inside Cordon, reversible)
    shadow             the account is in shadow mode: record what would have happened, do nothing
    awaiting_approval  above the account's tier, or a protected identity: a human decides
    above_tier         an L3 mailbox recommendation for an account below L3: recorded only
    halted             the kill switch is on: recorded only

Injection resistance is structural: DecisionInputs has no free-text field. The subject, body,
links and display names of the email never reach this module, so nothing an email says can
change which actions are planned, their tier, or the account's ceiling. The same principle as
the risk engine's additive-only LLM signal and D4's deterministic assessment.

Tiers (the account's ceiling, AutonomyPolicy.tier):
    L0 Observe       analyze and record; every action becomes a recommendation
    L1 Flag          label, triage status/priority, notify, open an investigation
    L2 Auto-triage   L1 + watchlist/blocklist inside Cordon, group a campaign, escalate
    L3 Remediation   L2 + produce a concrete mailbox-action recommendation for approval.
                     Cordon never executes it on the mailbox; see cordon_actions.DEFERRED_ACTIONS.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.autonomy.actions import BLOCK_SENDER_DOMAIN, FLAG_ACCOUNT_FOR_REVIEW, QUARANTINE_EMAIL
from app.autonomy.cordon_actions import (
    ACTION_SPECS,
    BLOCKLIST_DOMAIN,
    ESCALATE_PRIORITY,
    GROUP_CAMPAIGN,
    LABEL_CASE,
    NOTIFY,
    OPEN_INVESTIGATION,
    RECOMMEND_MAILBOX_REMEDIATION,
    SET_TRIAGE,
    WATCHLIST_IP,
    WATCHLIST_SENDER,
)

TIERS = ("L0", "L1", "L2", "L3")
OUTCOMES = ("performed", "shadow", "awaiting_approval", "above_tier", "halted")

_CONF_RANK = {"low": 0, "medium": 1, "high": 2}
_PRIORITY = ("low", "medium", "high", "critical")
_MAILBOX_ACTIONS = {QUARANTINE_EMAIL, BLOCK_SENDER_DOMAIN, FLAG_ACCOUNT_FOR_REVIEW}

# Stable rule ids, recorded on every audit row.
RULES: dict[str, str] = {
    "R1-LABEL": "Suspicious or malicious verdict: tag and triage the case",
    "R2-NOTIFY": "Malicious, or suspicious with at least medium confidence: notify the account",
    "R3-INVESTIGATE": "Suspicious or malicious verdict: make sure an investigation is open",
    "R4-WATCH-SENDER": "At least medium confidence and the sender is not an established correspondent: watch the sender",
    "R5-BLOCK-DOMAIN": "Investigation recommends blocking the sender domain (high confidence, unknown sender): blocklist it in Cordon",
    "R6-WATCH-IP": "High confidence and the sending IP is not shared mail-provider infrastructure: watch the IP",
    "R7-CAMPAIGN": "Linked to other recent cases by signature, link domain or IP: group them as a campaign",
    "R8-ESCALATE": "Part of a wave, or the sender's account looks taken over: escalate priority",
    "R9-MAILBOX": "Investigation recommends a mailbox action: propose it for human approval",
}


@dataclass(frozen=True)
class DecisionInputs:
    """Deterministic facts only. Deliberately no subject/body/narrative field."""

    verdict: str
    confidence: str  # "low" | "medium" | "high" (app.investigation.assessment)
    campaign_status: str = "one_off"  # "one_off" | "possible_campaign" | "wave"
    linked_case_ids: tuple[str, ...] = ()
    campaign_signature: str | None = None
    recommended_action: str | None = None  # from the autonomy catalog, or None
    recommended_tier: str | None = None
    ato_kind: str | None = None  # "external" | "lateral" | None
    sender_classification: str | None = None  # "established" | "first_contact" | ...
    sender_address: str | None = None
    sender_domain: str | None = None
    sending_ip: str | None = None
    ip_is_provider: bool = False
    hypothesis: str | None = None
    recipients: tuple[str, ...] = ()


@dataclass(frozen=True)
class PolicyView:
    tier: str = "L1"
    shadow_mode: bool = True
    kill_switch: bool = False
    exclusions: frozenset[str] = frozenset()
    blast_radius_limit: int = 10
    performed_in_window: int = 0  # automatic L2 actions already performed in the window


@dataclass(frozen=True)
class PlannedAction:
    action_type: str
    tier: str
    rule_id: str
    trigger: str
    target: str
    params: dict = field(default_factory=dict)
    outcome: str = "performed"
    within_tier: bool = True


def tier_at_or_below(action_tier: str, ceiling: str) -> bool:
    return TIERS.index(action_tier) <= TIERS.index(ceiling)


def _priority_for(verdict: str, confidence: str) -> str:
    base = {"low": 0, "medium": 1, "high": 2}[confidence]
    if verdict == "malicious":
        base = min(base + 1, 2)
    return _PRIORITY[base]


def _candidates(inp: DecisionInputs, case_id: str) -> list[tuple[str, str, str, str, dict]]:
    """(action_type, rule_id, trigger, target, params) the rules call for, before gating."""
    out: list[tuple[str, str, str, str, dict]] = []
    if inp.verdict not in ("suspicious", "malicious"):
        return out
    conf = _CONF_RANK.get(inp.confidence, 0)
    verdict_trigger = f"verdict:{inp.verdict}"

    tag = (inp.hypothesis or inp.verdict).replace("_", "-")
    out.append((LABEL_CASE, "R1-LABEL", verdict_trigger, f"case:{case_id}", {"tag": tag}))
    out.append((SET_TRIAGE, "R1-LABEL", verdict_trigger, f"case:{case_id}",
                {"status": "triaged", "priority": _priority_for(inp.verdict, inp.confidence)}))
    if inp.verdict == "malicious" or conf >= 1:
        out.append((NOTIFY, "R2-NOTIFY", verdict_trigger, "account", {}))
    out.append((OPEN_INVESTIGATION, "R3-INVESTIGATE", verdict_trigger, f"case:{case_id}", {}))

    if conf == 0:
        return out  # low confidence: label and investigate only

    if inp.sender_address and inp.sender_classification != "established":
        out.append((WATCHLIST_SENDER, "R4-WATCH-SENDER", f"confidence:{inp.confidence}",
                    f"sender:{inp.sender_address}", {"kind": "sender", "value": inp.sender_address}))
    if inp.recommended_action == BLOCK_SENDER_DOMAIN and inp.sender_domain:
        out.append((BLOCKLIST_DOMAIN, "R5-BLOCK-DOMAIN", f"recommendation:{BLOCK_SENDER_DOMAIN}",
                    f"domain:{inp.sender_domain}", {"kind": "domain", "value": inp.sender_domain}))
    if conf == 2 and inp.sending_ip and not inp.ip_is_provider:
        out.append((WATCHLIST_IP, "R6-WATCH-IP", "confidence:high",
                    f"ip:{inp.sending_ip}", {"kind": "ip", "value": inp.sending_ip}))
    if inp.campaign_status in ("wave", "possible_campaign") and inp.linked_case_ids:
        out.append((GROUP_CAMPAIGN, "R7-CAMPAIGN", f"campaign:{inp.campaign_status}", f"case:{case_id}",
                    {"case_ids": [case_id, *inp.linked_case_ids], "signature": inp.campaign_signature}))
    if inp.campaign_status == "wave" or inp.ato_kind:
        trigger = "campaign:wave" if inp.campaign_status == "wave" else f"account_takeover:{inp.ato_kind}"
        out.append((ESCALATE_PRIORITY, "R8-ESCALATE", trigger, f"case:{case_id}", {"priority": "critical"}))
    if inp.recommended_action in _MAILBOX_ACTIONS and inp.recommended_tier not in (None, "L0"):
        case_ids = [case_id, *(inp.linked_case_ids if inp.campaign_status == "wave" else ())]
        out.append((RECOMMEND_MAILBOX_REMEDIATION, "R9-MAILBOX", f"recommendation:{inp.recommended_action}",
                    f"case:{case_id}", {
                        "mailbox_action": inp.recommended_action,
                        "case_ids": case_ids,
                        "recipients": list(inp.recipients),
                        "sender_domain": inp.sender_domain,
                    }))
    return out


def plan(inp: DecisionInputs, policy: PolicyView, case_id: str) -> list[PlannedAction]:
    """Every action the rules call for, each gated to exactly one outcome. First match wins:
    kill switch, shadow mode, protected identity, tier ceiling, rate cap, else performed."""
    exclusions = frozenset(e.strip().lower() for e in policy.exclusions if e.strip())
    performed = policy.performed_in_window
    result: list[PlannedAction] = []
    for action_type, rule_id, trigger, target, params in _candidates(inp, case_id):
        spec = ACTION_SPECS[action_type]
        excluded = _identity_excluded(action_type, target, inp, exclusions)
        within = tier_at_or_below(spec.tier, policy.tier) and not excluded

        if policy.kill_switch:
            outcome = "halted"
        elif policy.shadow_mode:
            outcome = "shadow"
        elif excluded:
            outcome = "awaiting_approval"
        elif not tier_at_or_below(spec.tier, policy.tier):
            outcome = "above_tier" if spec.tier == "L3" else "awaiting_approval"
        elif spec.tier == "L3":
            # Within an L3 ceiling, "performing" a mailbox recommendation means queueing it
            # for a human. It is never executed against the mailbox.
            outcome = "awaiting_approval"
        elif spec.tier == "L2" and performed >= policy.blast_radius_limit:
            # The rate cap bounds actions that change how future mail is treated (lists,
            # campaigns, escalation). L1 bookkeeping on the case itself is not capped.
            outcome = "awaiting_approval"
            within = False
        else:
            outcome = "performed"
            if spec.tier == "L2":
                performed += 1
        result.append(PlannedAction(
            action_type=action_type, tier=spec.tier, rule_id=rule_id, trigger=trigger,
            target=target, params=params, outcome=outcome, within_tier=within,
        ))
    return result


def _identity_excluded(action_type: str, target: str, inp: DecisionInputs, exclusions: frozenset[str]) -> bool:
    """Protected identities (AutonomyPolicy.exclusions) are never auto-listed and never get a
    mailbox action without a human. Case-level bookkeeping (tag, triage, notify, investigate,
    group, escalate) stays automatic: it changes nothing about the identity."""
    if not exclusions:
        return False
    if action_type in (WATCHLIST_SENDER, BLOCKLIST_DOMAIN, WATCHLIST_IP):
        return target.split(":", 1)[1].lower() in exclusions or (
            action_type != WATCHLIST_IP
            and bool({x.lower() for x in (inp.sender_address, inp.sender_domain) if x} & exclusions)
        )
    if action_type == RECOMMEND_MAILBOX_REMEDIATION:
        return bool({x.lower() for x in (inp.sender_address, inp.sender_domain) if x} & exclusions)
    return False
