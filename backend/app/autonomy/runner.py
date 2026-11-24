"""Runs the D5 graduated-autonomy engine for a case and handles undo/approve/dismiss. The only
I/O layer for app.autonomy.engine (pure) and app.autonomy.cordon_actions (Cordon-owned writes).

Every planned action, performed or not, gets exactly one AutonomyAction audit row recording
the timestamp, case, trigger, tier, rule, mode (shadow/active), outcome, and the undo path.
Nothing here calls an ActionConnector: no mailbox, identity provider or other external system
is touched by any D5 path.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.autonomy.cordon_actions import (
    ACTION_SPECS,
    RECOMMEND_MAILBOX_REMEDIATION,
    ActionContext,
    Superseded,
    mailbox_summary,
)
from app.autonomy.engine import RULES, DecisionInputs, PlannedAction, PolicyView, plan
from app.db.models import AutonomyAction, AutonomyPolicy, Case, Investigation, User
from app.investigation.assessment import CONFIDENCE_SCORE

ENGINE = "d5"

_STATUS_FOR_OUTCOME = {
    "performed": "executed",
    "shadow": "shadow",
    "awaiting_approval": "pending_approval",
    "above_tier": "above_tier",
    "halted": "halted",
}


def policy_row_for(db: Session, account_id: uuid.UUID) -> AutonomyPolicy:
    """Get-or-create without committing (the caller owns the transaction)."""
    row = db.query(AutonomyPolicy).filter(AutonomyPolicy.account_id == account_id).first()
    if row is None:
        row = AutonomyPolicy(account_id=account_id)
        db.add(row)
        db.flush()
    return row


def decision_inputs(case: Case, investigation: Investigation | None) -> DecisionInputs:
    """Only deterministic fields: the case verdict, D4's assessment, and header metadata.
    No subject, body or narrative is read here."""
    from app.investigation.tools import HOSTED_MAIL_PROVIDERS

    report = (investigation.report if investigation is not None else None) or {}
    confidence = (report.get("confidence") or {}).get("level") or "low"
    campaign = report.get("campaign") or {}
    rec = report.get("recommendation") or {}
    artifacts = case.artifacts or {}
    sender = (case.from_addr or "").strip().lower() or None
    domain = None
    if sender and "@" in sender:
        from app.indicators.domain_utils import registrable_domain

        domain = registrable_domain(sender.rsplit("@", 1)[1])
    provider = artifacts.get("sending_provider")
    intel = (investigation.sender_intelligence if investigation is not None else None) or {}
    return DecisionInputs(
        verdict=case.verdict,
        confidence=confidence,
        campaign_status=campaign.get("status") or "one_off",
        linked_case_ids=tuple(str(i) for i in campaign.get("linked_case_ids") or []),
        campaign_signature=artifacts.get("campaign_signature"),
        recommended_action=rec.get("action"),
        recommended_tier=rec.get("suggested_tier"),
        ato_kind=(case.account_takeover or {}).get("kind"),
        sender_classification=intel.get("classification"),
        sender_address=sender,
        sender_domain=domain,
        sending_ip=artifacts.get("sending_ip"),
        ip_is_provider=bool(provider and provider in HOSTED_MAIL_PROVIDERS),
        hypothesis=(report.get("hypothesis") or {}).get("category"),
        recipients=tuple(a.lower() for a in case.to_addresses or []),
    )


def _performed_in_window(db: Session, account_id: uuid.UUID, row: AutonomyPolicy, now: datetime) -> int:
    start = now - timedelta(minutes=row.blast_radius_window_minutes)
    return (
        db.query(AutonomyAction)
        .filter(
            AutonomyAction.account_id == account_id,
            AutonomyAction.engine == ENGINE,
            AutonomyAction.actor == "system",
            AutonomyAction.tier == "L2",
            AutonomyAction.status.in_(("executed", "reversed")),
            AutonomyAction.created_at >= start,
        )
        .count()
    )


def _apply(db: Session, case: Case, row: AutonomyAction, actor: str, now: datetime) -> None:
    spec = ACTION_SPECS[row.action_type]
    ctx = ActionContext(
        db=db, account_id=case.account_id, case=case, action_id=row.id,
        params=dict(row.result.get("params") or {}), actor=actor, now=now,
    )
    with db.begin_nested():
        before = spec.apply(ctx)
    row.undo = {**(row.undo or {}), "before": before}


def run_for_case(db: Session, case: Case, *, now: datetime | None = None) -> list[AutonomyAction]:
    """Plan and (where allowed) perform the engine's actions for one case. Idempotent per
    (case, action type, target). Does not commit."""
    now = now or datetime.now(timezone.utc)
    investigation = (
        db.query(Investigation)
        .filter(Investigation.account_id == case.account_id, Investigation.case_id == case.id)
        .first()
    )
    policy_row = policy_row_for(db, case.account_id)
    policy = PolicyView(
        tier=policy_row.tier,
        shadow_mode=policy_row.shadow_mode,
        kill_switch=policy_row.kill_switch,
        exclusions=frozenset(policy_row.exclusions or []),
        blast_radius_limit=policy_row.blast_radius_limit,
        performed_in_window=_performed_in_window(db, case.account_id, policy_row, now),
    )
    planned = plan(decision_inputs(case, investigation), policy, str(case.id))

    done = {
        (r.action_type, r.target)
        for r in db.query(AutonomyAction.action_type, AutonomyAction.target).filter(
            AutonomyAction.case_id == case.id, AutonomyAction.engine == ENGINE
        )
    }
    snapshot = {"tier": policy.tier, "shadow_mode": policy.shadow_mode, "kill_switch": policy.kill_switch}
    rows: list[AutonomyAction] = []
    for p in planned:
        if (p.action_type, p.target) in done:
            continue
        row = _row_for(case, p, snapshot, now, investigation)
        db.add(row)
        db.flush()
        if p.outcome == "performed" or (p.outcome == "awaiting_approval" and p.action_type == RECOMMEND_MAILBOX_REMEDIATION and p.within_tier):
            try:
                _apply(db, case, row, "system", now)
            except Exception as exc:  # noqa: BLE001 - one failed action must not stop the rest
                row.status = "execution_failed"
                row.result = {**row.result, "error": type(exc).__name__}
        rows.append(row)
    db.flush()
    return rows


def _row_for(case: Case, p: PlannedAction, snapshot: dict, now: datetime, investigation) -> AutonomyAction:
    spec = ACTION_SPECS[p.action_type]
    report = (investigation.report if investigation is not None else None) or {}
    confidence_level = (report.get("confidence") or {}).get("level") or "low"
    description = spec.title
    if p.action_type == RECOMMEND_MAILBOX_REMEDIATION:
        description = f"Recommend: {mailbox_summary(p.params)}"
    elif "value" in p.params:
        description = f"{spec.title}: {p.params['value']}"
    elif p.action_type == "LABEL_CASE":
        description = f"{spec.title}: {p.params['tag']}"
    elif "priority" in p.params:
        description = f"{spec.title}: {p.params['priority']}"
    return AutonomyAction(
        id=uuid.uuid4(),
        account_id=case.account_id,
        created_at=now,
        case_id=case.id,
        trigger_finding_id=p.trigger,
        action_type=p.action_type,
        target=p.target,
        confidence=CONFIDENCE_SCORE.get(confidence_level, 0.4),
        policy_rule=snapshot,
        decision=p.outcome,
        status=_STATUS_FOR_OUTCOME[p.outcome],
        result={"params": p.params, "description": description, "rule": RULES[p.rule_id]},
        reversible=True,
        mapped_controls={},
        engine=ENGINE,
        tier=p.tier,
        rule_id=p.rule_id,
        mode="shadow" if snapshot["shadow_mode"] else "active",
        within_tier=p.within_tier,
        undo={"kind": p.action_type, "description": spec.undo_description},
        actor="system",
    )


def maybe_run_for_case(db: Session, case: Case) -> None:
    """Trigger hook. Never raises: autonomy must never break email analysis."""
    try:
        with db.begin_nested():
            run_for_case(db, case)
    except Exception:  # noqa: BLE001
        import logging

        logging.getLogger(__name__).exception("Autonomy engine failed for case %s", case.id)


# --- human decisions ---------------------------------------------------------------------

class AutonomyError(ValueError):
    pass


def _engine_row(row: AutonomyAction) -> None:
    if row.engine != ENGINE:
        raise AutonomyError("This action was recorded by the earlier autonomy engine and can't be changed here.")


def undo(db: Session, row: AutonomyAction, user: User, ip: str | None = None) -> AutonomyAction:
    _engine_row(row)
    if row.status != "executed":
        raise AutonomyError(f"Only a performed action can be undone (this one is {row.status}).")
    case = db.get(Case, row.case_id)
    now = datetime.now(timezone.utc)
    spec = ACTION_SPECS[row.action_type]
    try:
        with db.begin_nested():
            spec.undo(db, row.account_id, case, (row.undo or {}).get("before") or {}, now, user.email)
    except Superseded as exc:
        raise AutonomyError(f"Not undone: {exc}") from exc
    row.status = "reversed"
    row.reversed_by = user.email
    row.reversed_at = now
    log_event(db, event_type="autonomy_action_undone", account_id=row.account_id, user_id=user.id,
              detail={"action_id": str(row.id), "action_type": row.action_type, "case_id": str(row.case_id)},
              ip_address=ip)
    db.flush()
    return row


def approve(db: Session, row: AutonomyAction, user: User, ip: str | None = None) -> AutonomyAction:
    _engine_row(row)
    if row.status != "pending_approval":
        raise AutonomyError(f"Only an action awaiting approval can be approved (this one is {row.status}).")
    policy_row = policy_row_for(db, row.account_id)
    if policy_row.kill_switch:
        raise AutonomyError("The autonomy kill switch is on. Turn it off before approving actions.")
    now = datetime.now(timezone.utc)
    case = db.get(Case, row.case_id)
    if row.action_type == RECOMMEND_MAILBOX_REMEDIATION:
        # Recorded only. Nothing in Cordon executes a mailbox action at this rung.
        row.status = "approved"
    else:
        _apply(db, case, row, user.email, now)
        row.status = "executed"
        row.actor = user.email  # performed by a person, not the automatic budget
    row.decided_by, row.decided_at = user.email, now
    log_event(db, event_type="autonomy_action_approved", account_id=row.account_id, user_id=user.id,
              detail={"action_id": str(row.id), "action_type": row.action_type, "case_id": str(row.case_id)},
              ip_address=ip)
    db.flush()
    return row


def dismiss(db: Session, row: AutonomyAction, user: User, ip: str | None = None) -> AutonomyAction:
    _engine_row(row)
    if row.status != "pending_approval":
        raise AutonomyError(f"Only a pending recommendation can be dismissed (this one is {row.status}).")
    now = datetime.now(timezone.utc)
    before = (row.undo or {}).get("before")
    if before and row.action_type == RECOMMEND_MAILBOX_REMEDIATION:
        ACTION_SPECS[row.action_type].undo(db, row.account_id, db.get(Case, row.case_id), before, now, user.email)
    row.status = "dismissed"
    row.decided_by, row.decided_at = user.email, now
    log_event(db, event_type="autonomy_action_dismissed", account_id=row.account_id, user_id=user.id,
              detail={"action_id": str(row.id), "action_type": row.action_type, "case_id": str(row.case_id)},
              ip_address=ip)
    db.flush()
    return row


def set_kill_switch(db: Session, account_id: uuid.UUID, on: bool, user: User, ip: str | None = None) -> tuple[AutonomyPolicy, int]:
    row = policy_row_for(db, account_id)
    halted = 0
    row.kill_switch = on
    if on:
        row.halted_at = datetime.now(timezone.utc)
        halted = (
            db.query(AutonomyAction)
            .filter(AutonomyAction.account_id == account_id, AutonomyAction.status == "pending_approval")
            .update({"status": "halted"}, synchronize_session=False)
        )
    log_event(db, event_type="autonomy_kill_switch_on" if on else "autonomy_kill_switch_off",
              account_id=account_id, user_id=user.id, detail={"halted_pending_count": halted}, ip_address=ip)
    db.flush()
    return row, halted
