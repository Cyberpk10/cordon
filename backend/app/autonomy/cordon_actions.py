"""Cordon-owned, reversible actions for the graduated-autonomy engine (D5).

Every action here changes only Cordon's own records: a case's tags, triage status and
priority, an in-app notification, an investigation, the account's in-Cordon watch/blocklist,
a campaign grouping. Each has an explicit undo, and the catalog refuses to load if any entry
lacks one. "An action with no undo path is forbidden at any auto tier" is therefore structural,
not a policy setting.

`apply` returns the before-state its undo needs. It is stored on the audit row
(AutonomyAction.undo["before"]). `undo` restores it, and raises Superseded instead of
overwriting a value a person has changed since. A person's edit always wins over an engine undo.

OUT OF SCOPE for this rung, deliberately (see DEFERRED_ACTIONS): any write to a real mailbox
(quarantine, move, delete, transport/inbox rules), which needs mailbox write scopes and CASA
verification, session revocation, and any action on a third-party system. Those appear only
as RECOMMEND_MAILBOX_REMEDIATION, a proposal a human approves and then carries out themselves.
Approving it records the decision; nothing in this package executes it. The M6
app.autonomy.graph_connector stays in the codebase for the next rung but is not called by
any automatic path.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.db.models import Case, CaseCampaign, CordonListEntry, Investigation, Notification

LABEL_CASE = "LABEL_CASE"
SET_TRIAGE = "SET_TRIAGE"
NOTIFY = "NOTIFY"
OPEN_INVESTIGATION = "OPEN_INVESTIGATION"
WATCHLIST_SENDER = "WATCHLIST_SENDER"
BLOCKLIST_DOMAIN = "BLOCKLIST_DOMAIN"
WATCHLIST_IP = "WATCHLIST_IP"
GROUP_CAMPAIGN = "GROUP_CAMPAIGN"
ESCALATE_PRIORITY = "ESCALATE_PRIORITY"
RECOMMEND_MAILBOX_REMEDIATION = "RECOMMEND_MAILBOX_REMEDIATION"

DEFERRED_ACTIONS: dict[str, str] = {
    "MAILBOX_QUARANTINE": "Moving real mail needs mailbox write scopes and CASA verification. Next rung.",
    "MAILBOX_DELETE": "Never automatic. Not planned for any tier.",
    "MAILBOX_RULES": "Transport/inbox rules need mailbox write scopes. Next rung.",
    "SESSION_REVOKE": "Irreversible (no un-revoke API). Human-only.",
    "THIRD_PARTY": "No action on any system outside Cordon at this rung.",
}


class Superseded(Exception):
    """A person changed the value after the engine set it; undo refuses to overwrite it."""


@dataclass
class ActionContext:
    db: Session
    account_id: uuid.UUID
    case: Case
    action_id: uuid.UUID
    params: dict
    actor: str
    now: datetime


Apply = Callable[[ActionContext], dict]
Undo = Callable[[Session, uuid.UUID, Case, dict, datetime, str], None]


@dataclass(frozen=True)
class ActionSpec:
    type: str
    tier: str
    title: str
    undo_description: str
    apply: Apply
    undo: Undo


# --- L1 ---------------------------------------------------------------------------------

def _apply_label(ctx: ActionContext) -> dict:
    tag = ctx.params["tag"]
    tags = list(ctx.case.engine_tags or [])
    had = tag in tags
    if not had:
        ctx.case.engine_tags = [*tags, tag]
    return {"tag": tag, "had_tag": had}


def _undo_label(db, account_id, case, before, now, actor) -> None:
    if before.get("had_tag"):
        return
    case.engine_tags = [t for t in (case.engine_tags or []) if t != before["tag"]]


def _apply_triage(ctx: ActionContext) -> dict:
    before = {"status": ctx.case.status, "priority": ctx.case.priority}
    ctx.case.status = ctx.params["status"]
    ctx.case.priority = ctx.params["priority"]
    return {**before, "set_status": ctx.params["status"], "set_priority": ctx.params["priority"]}


def _undo_triage(db, account_id, case, before, now, actor) -> None:
    if case.status != before["set_status"] or case.priority != before["set_priority"]:
        raise Superseded("The case's status or priority was changed after Cordon set it.")
    case.status, case.priority = before["status"], before["priority"]


def _apply_notify(ctx: ActionContext) -> dict:
    case = ctx.case
    sender = case.from_addr or "an unknown sender"
    note = Notification(
        account_id=ctx.account_id,
        case_id=case.id,
        action_id=ctx.action_id,
        title=f"{case.verdict.capitalize()} email flagged",
        body=f"From {sender}: {(case.subject or '(no subject)')[:140]}. Cordon rated it {case.verdict} ({case.score}/100).",
        created_at=ctx.now,
    )
    ctx.db.add(note)
    ctx.db.flush()
    return {"notification_id": str(note.id)}


def _undo_notify(db, account_id, case, before, now, actor) -> None:
    note = db.get(Notification, uuid.UUID(before["notification_id"]))
    if note is not None and note.account_id == account_id and note.retracted_at is None:
        note.retracted_at = now


def _apply_investigation(ctx: ActionContext) -> dict:
    existing = (
        ctx.db.query(Investigation)
        .filter(Investigation.account_id == ctx.account_id, Investigation.case_id == ctx.case.id)
        .first()
    )
    if existing is not None:
        return {"created": False, "investigation_id": str(existing.id)}
    from app.investigation.build import save_investigation  # local: build imports the runner

    inv = save_investigation(ctx.db, ctx.account_id, case=ctx.case, trigger="auto", now=ctx.now, use_llm=False)
    return {"created": True, "investigation_id": str(inv.id)}


def _undo_investigation(db, account_id, case, before, now, actor) -> None:
    if not before.get("created"):
        return
    inv = db.get(Investigation, uuid.UUID(before["investigation_id"]))
    if inv is not None and inv.account_id == account_id:
        db.delete(inv)


# --- L2 ---------------------------------------------------------------------------------

def _list_apply(list_name: str) -> Apply:
    def apply(ctx: ActionContext) -> dict:
        kind, value = ctx.params["kind"], ctx.params["value"].lower()
        existing = (
            ctx.db.query(CordonListEntry)
            .filter(
                CordonListEntry.account_id == ctx.account_id,
                CordonListEntry.kind == kind,
                CordonListEntry.list_name == list_name,
                CordonListEntry.value == value,
                CordonListEntry.active.is_(True),
            )
            .first()
        )
        if existing is not None:
            return {"entry_id": None, "already_listed": str(existing.id), "list": list_name, "kind": kind, "value": value}
        entry = CordonListEntry(
            account_id=ctx.account_id, kind=kind, list_name=list_name, value=value, active=True,
            source_action_id=ctx.action_id, added_by=ctx.actor, reason=f"case {ctx.case.id}",
            created_at=ctx.now,
        )
        ctx.db.add(entry)
        ctx.db.flush()
        return {"entry_id": str(entry.id), "list": list_name, "kind": kind, "value": value}

    return apply


def _undo_list(db, account_id, case, before, now, actor) -> None:
    if not before.get("entry_id"):
        return  # it was already listed before this action; leave it
    entry = db.get(CordonListEntry, uuid.UUID(before["entry_id"]))
    if entry is not None and entry.account_id == account_id and entry.active:
        entry.active = False
        entry.removed_at = now
        entry.removed_by = actor


def _apply_campaign(ctx: ActionContext) -> dict:
    ids = []
    for raw in ctx.params["case_ids"]:
        try:
            ids.append(uuid.UUID(str(raw)))
        except ValueError:
            continue
    cases = ctx.db.query(Case).filter(Case.account_id == ctx.account_id, Case.id.in_(ids)).all()
    existing_ids = {c.campaign_id for c in cases if c.campaign_id is not None}
    created = False
    if existing_ids:
        campaign = ctx.db.get(CaseCampaign, sorted(existing_ids, key=str)[0])
    else:
        campaign = CaseCampaign(
            account_id=ctx.account_id,
            signature=ctx.params.get("signature"),
            title=f"Campaign: {(ctx.case.subject or ctx.case.from_addr or 'linked emails')[:80]}",
            created_by_action_id=ctx.action_id,
            created_at=ctx.now,
        )
        ctx.db.add(campaign)
        ctx.db.flush()
        created = True
    set_ids = []
    for c in cases:
        if c.campaign_id is None:
            c.campaign_id = campaign.id
            set_ids.append(str(c.id))
    return {"campaign_id": str(campaign.id), "created": created, "set_case_ids": set_ids}


def _undo_campaign(db, account_id, case, before, now, actor) -> None:
    campaign_id = uuid.UUID(before["campaign_id"])
    ids = [uuid.UUID(i) for i in before.get("set_case_ids", [])]
    for c in db.query(Case).filter(Case.account_id == account_id, Case.id.in_(ids)).all():
        if c.campaign_id == campaign_id:
            c.campaign_id = None
    db.flush()
    if before.get("created"):
        remaining = db.query(Case).filter(Case.campaign_id == campaign_id).count()
        campaign = db.get(CaseCampaign, campaign_id)
        if remaining == 0 and campaign is not None and campaign.account_id == account_id:
            db.delete(campaign)


def _apply_escalate(ctx: ActionContext) -> dict:
    before = {"status": ctx.case.status, "priority": ctx.case.priority}
    ctx.case.priority = ctx.params["priority"]
    ctx.case.status = "escalated"
    return {**before, "set_status": "escalated", "set_priority": ctx.params["priority"]}


_undo_escalate = _undo_triage


# --- L3 ---------------------------------------------------------------------------------

def _apply_mailbox_recommendation(ctx: ActionContext) -> dict:
    """Queues the proposal for a human: one notification. Nothing touches a mailbox."""
    n = len(ctx.params.get("case_ids") or [])
    note = Notification(
        account_id=ctx.account_id,
        case_id=ctx.case.id,
        action_id=ctx.action_id,
        title="Approval needed: mailbox remediation",
        body=f"Cordon recommends: {mailbox_summary(ctx.params)}. Covers {n} message(s). Nothing has been done to any mailbox.",
        created_at=ctx.now,
    )
    ctx.db.add(note)
    ctx.db.flush()
    return {"notification_id": str(note.id)}


def mailbox_summary(params: dict) -> str:
    n = len(params.get("case_ids") or [])
    action = params.get("mailbox_action")
    if action == "BLOCK_SENDER_DOMAIN":
        return f"block {params.get('sender_domain') or 'the sender domain'} in your mail system and quarantine {n} message(s)"
    if action == "FLAG_ACCOUNT_FOR_REVIEW":
        return f"review the sender's account (sign-ins, sessions, mailbox rules) and quarantine {n} message(s)"
    return f"quarantine {n} message(s)"


ACTION_SPECS: dict[str, ActionSpec] = {
    s.type: s
    for s in (
        ActionSpec(LABEL_CASE, "L1", "Tag the case", "Remove the tag", _apply_label, _undo_label),
        ActionSpec(SET_TRIAGE, "L1", "Set triage status and priority", "Restore the previous status and priority",
                   _apply_triage, _undo_triage),
        ActionSpec(NOTIFY, "L1", "Notify the account", "Retract the notification", _apply_notify, _undo_notify),
        ActionSpec(OPEN_INVESTIGATION, "L1", "Open an investigation",
                   "Delete the investigation if Cordon opened it", _apply_investigation, _undo_investigation),
        ActionSpec(WATCHLIST_SENDER, "L2", "Add the sender to the Cordon watchlist", "Remove the watchlist entry",
                   _list_apply("watch"), _undo_list),
        ActionSpec(BLOCKLIST_DOMAIN, "L2", "Add the sender domain to the Cordon blocklist",
                   "Remove the blocklist entry", _list_apply("block"), _undo_list),
        ActionSpec(WATCHLIST_IP, "L2", "Add the sending IP to the Cordon watchlist", "Remove the watchlist entry",
                   _list_apply("watch"), _undo_list),
        ActionSpec(GROUP_CAMPAIGN, "L2", "Group linked cases into a campaign",
                   "Ungroup the cases (and delete the campaign if Cordon created it)", _apply_campaign, _undo_campaign),
        ActionSpec(ESCALATE_PRIORITY, "L2", "Escalate priority to critical", "Restore the previous status and priority",
                   _apply_escalate, _undo_escalate),
        ActionSpec(RECOMMEND_MAILBOX_REMEDIATION, "L3", "Recommend mailbox remediation",
                   "Withdraw the recommendation", _apply_mailbox_recommendation, _undo_notify),
    )
}


def validate_catalog(specs: dict[str, ActionSpec]) -> None:
    """Refuse any action without an undo path, or outside L1-L3. Run at import."""
    for spec in specs.values():
        if spec.undo is None or not callable(spec.undo) or not spec.undo_description:
            raise RuntimeError(f"Autonomy action {spec.type} has no undo path; refusing to load.")
        if spec.tier not in ("L1", "L2", "L3"):
            raise RuntimeError(f"Autonomy action {spec.type} has invalid tier {spec.tier!r}.")


validate_catalog(ACTION_SPECS)
