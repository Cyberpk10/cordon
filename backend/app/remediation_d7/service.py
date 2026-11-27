"""D7 service: policy, directive issue/claim/result, undo, rate cap, kill switch, feedback.

The protocol with the Gmail add-on (the only thing holding a mailbox credential):

  /inbound  analyze one message -> gate -> maybe ISSUE a signed directive for that one id
  /claim    right before acting: re-check kill switch, enabled, halt, expiry, single use
  /result   the add-on reports executed | aborted | failed; executed -> notify (+ log)

Every directive names exactly one Gmail message id. Nothing in this module accepts a query or
a list of ids. Undo directives restore INBOX and are allowed even with the kill switch on or
D7 disabled: putting mail back is always safe.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.auth.audit_log import log_event
from app.core.config import settings
from app.db.models import (
    AutonomyPolicy,
    CalibrationRun,
    Case,
    Investigation,
    MailboxAction,
    MailboxRemediationPolicy,
    Notification,
    RuleFeedback,
)
from app.remediation_d7 import directives as D
from app.remediation_d7.gate import GateResult, evaluate_gate

FP_TAG = "false-positive-undo"
ACTIVE_MOVE_STATUSES = ("issued", "claimed", "executed", "undone")
RESTORE_WATCH_DAYS = 7


class D7Error(ValueError):
    """A request the protocol refuses (bad signature, wrong state, ...). Routes map to 409."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return _aware(dt).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---- policy -----------------------------------------------------------------------------------


def get_policy(db: Session, account_id: uuid.UUID) -> MailboxRemediationPolicy | None:
    return db.query(MailboxRemediationPolicy).filter(MailboxRemediationPolicy.account_id == account_id).first()


def ensure_policy(db: Session, account_id: uuid.UUID) -> MailboxRemediationPolicy:
    row = get_policy(db, account_id)
    if row is None:
        row = MailboxRemediationPolicy(
            account_id=account_id, enabled=False,
            score_floor=settings.d7_default_score_floor,
            max_moves_per_hour=settings.d7_default_max_moves_per_hour,
            notify_email=False,
        )
        db.add(row)
        db.flush()
    return row


def kill_switch_on(db: Session, account_id: uuid.UUID) -> bool:
    row = db.query(AutonomyPolicy).filter(AutonomyPolicy.account_id == account_id).first()
    return bool(row and row.kill_switch)


def mailbox_allowlisted(mailbox: str | None) -> bool:
    return bool(mailbox) and mailbox.strip().lower() in settings.d7_allowed_mailboxes


def latest_calibration(db: Session, account_id: uuid.UUID, *, complete: bool = True) -> CalibrationRun | None:
    q = db.query(CalibrationRun).filter(CalibrationRun.account_id == account_id)
    if complete:
        q = q.filter(CalibrationRun.status == "complete")
    return q.order_by(CalibrationRun.started_at.desc()).first()


def calibration_covers(policy: MailboxRemediationPolicy, now: datetime) -> tuple[bool, str | None]:
    """Enable needs a complete calibration within the max age, at a floor at or below the
    current one (raising the floor only moves fewer messages; lowering it needs a new run)."""
    if policy.calibrated_at is None or policy.calibrated_floor is None:
        return False, "Run a calibration first."
    if now - _aware(policy.calibrated_at) > timedelta(days=settings.d7_calibration_max_age_days):
        return False, f"The last calibration is older than {settings.d7_calibration_max_age_days} days; run it again."
    if policy.score_floor < policy.calibrated_floor:
        return False, (f"The floor ({policy.score_floor}) is below the calibrated floor "
                       f"({policy.calibrated_floor}); run a calibration at the new floor.")
    return True, None


def enable_blockers(policy: MailboxRemediationPolicy, now: datetime) -> list[str]:
    out = []
    if not settings.d7_directive_secret:
        out.append("D7_DIRECTIVE_SECRET is not set on the server.")
    if not policy.mailbox_address or policy.owner_user_id is None:
        out.append("Set the mailbox (your own Gmail address) first.")
    elif not mailbox_allowlisted(policy.mailbox_address):
        out.append("This mailbox is not in D7_ALLOWED_MAILBOXES. Any mailbox other than the owner's own "
                   "test deployment needs Google's CASA assessment first.")
    ok, why = calibration_covers(policy, now)
    if not ok:
        out.append(why)
    return out


def moves_in_window(db: Session, account_id: uuid.UUID, now: datetime) -> int:
    since = now - timedelta(hours=1)
    rows = (
        db.query(MailboxAction)
        .filter(MailboxAction.account_id == account_id, MailboxAction.kind == "move",
                MailboxAction.status.in_(ACTIVE_MOVE_STATUSES))
        .all()
    )
    return sum(1 for r in rows if _aware(r.issued_at) >= since)


def halt(db: Session, policy: MailboxRemediationPolicy, reason: str, now: datetime, detail: str) -> None:
    policy.halted_at = now
    policy.halt_reason = reason
    db.add(Notification(
        account_id=policy.account_id, case_id=None, action_id=None,
        title="Auto-quarantine halted",
        body=detail + " No more messages will be moved until you resume it in Settings.",
    ))
    log_event(db, event_type="d7_halted", account_id=policy.account_id, detail={"reason": reason, "detail": detail})


# ---- gate on a case ---------------------------------------------------------------------------


def rule_score_of(case: Case) -> int:
    return int(case.score or 0) - int(case.llm_intent_risk or 0)


def rules_synthesis(db: Session, case: Case) -> dict | None:
    """A fresh rules-only D6 run on the stored D4 report. The stored record may carry LLM
    wording; the gate never depends on it (and stances never come from text anyway)."""
    from app.orchestration.orchestrator import run_orchestration

    inv = (
        db.query(Investigation)
        .filter(Investigation.account_id == case.account_id, Investigation.case_id == case.id)
        .first()
    )
    if inv is None:
        return None
    record, _ = run_orchestration(db, case, use_llm=False, investigation=inv)
    return record["synthesis"]


def gate_for_case(db: Session, case: Case, floor: int) -> GateResult:
    synthesis = rules_synthesis(db, case) if case.verdict == "malicious" else None
    return evaluate_gate(verdict=case.verdict, rule_score=rule_score_of(case), synthesis=synthesis, floor=floor)


# ---- directives -------------------------------------------------------------------------------


def directive_for(row: MailboxAction) -> dict:
    return D.build({
        "id": str(row.id), "kind": row.kind, "gmail_message_id": row.gmail_message_id,
        "fingerprint": row.fingerprint, "label": row.label, "nonce": row.nonce,
        "expires_at": _iso(row.expires_at),
    }, settings.d7_directive_secret)


def _new_row(*, account_id, case_id, kind, mailbox, gmail_message_id, fingerprint, ttl, now, actor,
             gate=None, parent_id=None, undo_source=None) -> MailboxAction:
    return MailboxAction(
        id=uuid.uuid4(), account_id=account_id, case_id=case_id, parent_id=parent_id, kind=kind,
        status="issued", mailbox_address=mailbox, gmail_message_id=gmail_message_id,
        fingerprint=fingerprint, label=settings.d7_quarantine_label, nonce=secrets.token_hex(16),
        gate=gate, issued_at=now, expires_at=now + timedelta(seconds=ttl), actor=actor,
        undo_source=undo_source,
    )


def decide_and_maybe_issue(
    db: Session, *, case: Case, policy: MailboxRemediationPolicy, mailbox: str,
    gmail_message_id: str, fingerprint: str, now: datetime | None = None,
) -> tuple[GateResult, dict | None, list[str]]:
    """Gate the case; issue a move directive only when the gate passes AND every issue-time
    condition holds. Returns (gate, directive or None, reasons a passing gate was withheld)."""
    now = now or utcnow()
    gate = gate_for_case(db, case, policy.score_floor)
    log_event(db, event_type="d7_gate_evaluated", account_id=case.account_id, detail={
        "case_id": str(case.id), "gmail_message_id": gmail_message_id, **gate.as_dict(),
    })
    if not gate.passed:
        return gate, None, []

    prior = (
        db.query(MailboxAction)
        .filter(MailboxAction.account_id == case.account_id, MailboxAction.kind == "move",
                MailboxAction.gmail_message_id == gmail_message_id)
        .order_by(MailboxAction.issued_at.desc())
        .first()
    )
    if prior is not None:
        if prior.status == "undone":
            return gate, None, ["The owner restored this message before; Cordon will not move it again."]
        if prior.status == "executed":
            return gate, None, ["Already moved."]
        if prior.status in ("issued", "claimed") and _aware(prior.expires_at) > now:
            return gate, directive_for(prior), []

    withheld = []
    if not settings.d7_directive_secret:
        withheld.append("D7_DIRECTIVE_SECRET is not set on the server.")
    if not policy.enabled:
        withheld.append("Auto-quarantine is not enabled.")
    if policy.halted_at is not None:
        withheld.append(f"Auto-quarantine is halted ({policy.halt_reason}).")
    if kill_switch_on(db, case.account_id):
        withheld.append("The kill switch is on.")
    if not mailbox_allowlisted(mailbox):
        withheld.append("Mailbox not in D7_ALLOWED_MAILBOXES (CASA required for any other mailbox).")
    ok, why = calibration_covers(policy, now)
    if not ok:
        withheld.append(why)
    if not withheld and moves_in_window(db, case.account_id, now) >= policy.max_moves_per_hour:
        halt(db, policy, "rate_cap", now,
             f"More than {policy.max_moves_per_hour} messages qualified for auto-quarantine within an hour.")
        withheld.append("Rate cap reached: auto-quarantine halted.")
    if withheld:
        log_event(db, event_type="d7_directive_withheld", account_id=case.account_id,
                  detail={"case_id": str(case.id), "reasons": withheld})
        return gate, None, withheld

    row = _new_row(
        account_id=case.account_id, case_id=case.id, kind="move", mailbox=mailbox,
        gmail_message_id=gmail_message_id, fingerprint=fingerprint,
        ttl=settings.d7_move_directive_ttl_seconds, now=now, actor="cordon:d7", gate=gate.as_dict(),
    )
    db.add(row)
    db.flush()
    log_event(db, event_type="d7_move_issued", account_id=case.account_id,
              detail={"action_id": str(row.id), "case_id": str(case.id), "gmail_message_id": gmail_message_id})
    return gate, directive_for(row), []


def _row_for_directive(db: Session, account_id: uuid.UUID, d: dict) -> MailboxAction:
    if not D.verify(d, settings.d7_directive_secret):
        raise D7Error("Directive signature is invalid.")
    try:
        row_id = uuid.UUID(d["id"])
    except ValueError as exc:
        raise D7Error("Unknown directive.") from exc
    row = db.get(MailboxAction, row_id)
    if row is None or row.account_id != account_id:
        raise D7Error("Unknown directive.")
    if (row.nonce, row.gmail_message_id, row.fingerprint, row.kind, row.label) != (
        d["nonce"], d["gmail_message_id"], d["fingerprint"], d["kind"], d["label"]
    ):
        raise D7Error("Directive does not match the issued action.")
    return row


def claim(db: Session, account_id: uuid.UUID, d: dict, now: datetime | None = None) -> dict:
    """The last check before the add-on touches the mailbox. Single use: an issued directive
    becomes claimed exactly once."""
    now = now or utcnow()
    row = _row_for_directive(db, account_id, d)
    if row.status != "issued":
        raise D7Error(f"Directive already {row.status}.")
    if _aware(row.expires_at) <= now:
        row.status, row.detail = "expired", "Expired before it was claimed."
        return {"go": False, "reason": "expired"}
    if row.kind == "move":
        policy = get_policy(db, account_id)
        reason = None
        if kill_switch_on(db, account_id):
            reason = "kill_switch"
        elif policy is None or not policy.enabled:
            reason = "disabled"
        elif policy.halted_at is not None:
            reason = "halted"
        elif not mailbox_allowlisted(row.mailbox_address):
            reason = "mailbox_not_allowed"
        if reason:
            row.status, row.detail = "aborted", f"No-go at claim: {reason}."
            log_event(db, event_type="d7_claim_refused", account_id=account_id,
                      detail={"action_id": str(row.id), "reason": reason})
            return {"go": False, "reason": reason}
    row.status, row.claimed_at = "claimed", now
    return {"go": True}


def _notify_moved(db: Session, row: MailboxAction, case: Case | None) -> None:
    gate = row.gate or {}
    sender = (case.from_addr if case else None) or "unknown sender"
    subject = ((case.subject if case else None) or "(no subject)")[:120]
    db.add(Notification(
        account_id=row.account_id, case_id=row.case_id, action_id=row.id,
        title="Moved to Cordon Quarantine",
        body=(f"Cordon moved \"{subject}\" from {sender} (rules score {gate.get('score')}) out of your inbox "
              f"into the \"{row.label}\" label. Nothing was deleted. Not phishing? Undo restores it to your inbox."),
    ))


def _record_false_positive(db: Session, move: MailboxAction, source: str) -> None:
    case = db.get(Case, move.case_id) if move.case_id else None
    if case is not None:
        for ind in case.indicators or []:
            ind_id = ind.get("id") if isinstance(ind, dict) else None
            if ind_id:
                db.add(RuleFeedback(account_id=move.account_id, case_id=case.id, action_id=move.id,
                                    indicator_id=ind_id, kind="false_positive", source=source))
        if FP_TAG not in (case.engine_tags or []):
            case.engine_tags = list(case.engine_tags or []) + [FP_TAG]
    db.add(Notification(
        account_id=move.account_id, case_id=move.case_id, action_id=move.id,
        title="Restored to your inbox",
        body="The message Cordon quarantined is back in your inbox. Recorded as a false positive "
             "against the rules that fired.",
    ))


def _mark_undone(db: Session, move: MailboxAction, source: str, now: datetime) -> None:
    move.status, move.undone_at, move.undo_source = "undone", now, source
    _record_false_positive(db, move, source)
    log_event(db, event_type="d7_move_undone", account_id=move.account_id,
              detail={"action_id": str(move.id), "source": source})


def report_result(db: Session, account_id: uuid.UUID, d: dict, status: str, detail: str | None,
                  now: datetime | None = None) -> dict:
    now = now or utcnow()
    row = _row_for_directive(db, account_id, d)
    # Executed needs a claim; an abort may be reported before claiming (e.g. the add-on's own
    # fingerprint re-check failed, so it never asked to act).
    allowed = ("claimed",) if status == "executed" else ("issued", "claimed")
    if row.status not in allowed:
        raise D7Error(f"Directive is {row.status}; cannot record {status}.")
    row.detail = (detail or "")[:500] or None
    insert_notice = False
    if status == "executed":
        row.status, row.executed_at = "executed", now
        case = db.get(Case, row.case_id) if row.case_id else None
        if row.kind == "move":
            _notify_moved(db, row, case)
            policy = get_policy(db, account_id)
            insert_notice = bool(policy and policy.notify_email)
        else:
            move = db.get(MailboxAction, row.parent_id) if row.parent_id else None
            if move is not None and move.status == "executed":
                _mark_undone(db, move, row.undo_source or "app", now)
    else:
        row.status = status  # aborted | failed
    log_event(db, event_type=f"d7_{row.kind}_{row.status}", account_id=account_id,
              detail={"action_id": str(row.id), "gmail_message_id": row.gmail_message_id, "detail": row.detail})
    return {"recorded": row.status, "insert_notice": insert_notice}


# ---- undo -------------------------------------------------------------------------------------


def request_undo(db: Session, move: MailboxAction, *, source: str, actor: str,
                 now: datetime | None = None) -> dict:
    """Queue (or return the pending) single-message undo directive for an executed move."""
    now = now or utcnow()
    if move.kind != "move" or move.status != "executed":
        raise D7Error(f"Only a completed move can be undone (this one is {move.status}).")
    if not settings.d7_directive_secret:
        raise D7Error("D7_DIRECTIVE_SECRET is not set on the server.")
    pending = (
        db.query(MailboxAction)
        .filter(MailboxAction.parent_id == move.id, MailboxAction.kind == "undo",
                MailboxAction.status.in_(("issued", "claimed")))
        .first()
    )
    if pending is not None and _aware(pending.expires_at) > now:
        return directive_for(pending)
    row = _new_row(
        account_id=move.account_id, case_id=move.case_id, kind="undo", mailbox=move.mailbox_address,
        gmail_message_id=move.gmail_message_id, fingerprint=move.fingerprint,
        ttl=settings.d7_undo_directive_ttl_seconds, now=now, actor=actor, parent_id=move.id,
        undo_source=source,
    )
    db.add(row)
    db.flush()
    log_event(db, event_type="d7_undo_requested", account_id=move.account_id,
              detail={"action_id": str(row.id), "move_id": str(move.id), "source": source, "actor": actor})
    return directive_for(row)


def find_executed_move(db: Session, account_id: uuid.UUID, gmail_message_id: str) -> MailboxAction | None:
    return (
        db.query(MailboxAction)
        .filter(MailboxAction.account_id == account_id, MailboxAction.kind == "move",
                MailboxAction.gmail_message_id == gmail_message_id, MailboxAction.status == "executed")
        .order_by(MailboxAction.issued_at.desc())
        .first()
    )


def record_manual_restore(db: Session, account_id: uuid.UUID, action_id: uuid.UUID, gmail_message_id: str,
                          now: datetime | None = None) -> bool:
    """The owner moved it back in Gmail themselves: same outcome as an undo."""
    now = now or utcnow()
    move = db.get(MailboxAction, action_id)
    if (move is None or move.account_id != account_id or move.kind != "move"
            or move.gmail_message_id != gmail_message_id or move.status != "executed"):
        return False
    _mark_undone(db, move, "manual", now)
    return True


def pending_for_executor(db: Session, account_id: uuid.UUID, now: datetime | None = None) -> dict:
    now = now or utcnow()
    undos = (
        db.query(MailboxAction)
        .filter(MailboxAction.account_id == account_id, MailboxAction.kind == "undo",
                MailboxAction.status == "issued")
        .order_by(MailboxAction.issued_at)
        .all()
    )
    since = now - timedelta(days=RESTORE_WATCH_DAYS)
    moves = (
        db.query(MailboxAction)
        .filter(MailboxAction.account_id == account_id, MailboxAction.kind == "move",
                MailboxAction.status == "executed")
        .all()
    )
    pending_parent_ids = {u.parent_id for u in undos}
    return {
        "undos": [directive_for(u) for u in undos if _aware(u.expires_at) > now][:20],
        "quarantined": [
            {"action_id": str(m.id), "gmail_message_id": m.gmail_message_id}
            for m in moves
            if _aware(m.executed_at or m.issued_at) >= since and m.id not in pending_parent_ids
        ][:50],
        "label": settings.d7_quarantine_label,
    }
