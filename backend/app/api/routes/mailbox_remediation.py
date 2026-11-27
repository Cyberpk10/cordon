"""D7 live auto-quarantine routes.

- /v1/remediation/*  (API key): the Gmail add-on's loop. Owner only: the key's user must be the
  policy's owner and `mailbox` must be the policy's mailbox, or the call is refused (403).
- /api/remediation/mailbox/*  (JWT): the owner's settings, calibration report, actions, undo.

See app.remediation_d7 for the protocol and the gate.
"""

from __future__ import annotations

import hashlib
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.analysis.public_contract import public_verdict
from app.api.routes.analyze import persist_case_and_build_response
from app.api.routes.v1 import _lookup_or_run, _validated_raw_bytes
from app.auth.api_keys import api_key_rate_limit_key, get_api_key
from app.auth.audit_log import log_event
from app.auth.dependencies import get_current_user, require_admin
from app.auth.rate_limit import API_KEY_ANALYZE_RATE_LIMIT, limiter
from app.core.config import settings
from app.db.models import ApiKey, CalibrationRun, Case, MailboxAction, RuleFeedback, User
from app.db.session import get_db
from app.models.schemas import (
    D7AddonUndoRequest,
    D7CalibrationBatchRequest,
    D7CalibrationStartRequest,
    D7ClaimRequest,
    D7InboundRequest,
    D7InboundResponse,
    D7ManualRestoreRequest,
    D7PolicyUpdate,
    D7ResultRequest,
)
from app.remediation_d7 import calibration as CAL
from app.remediation_d7 import service as S
from app.sender_baseline.loader import record_observation

v1_router = APIRouter(prefix="/v1/remediation", tags=["d7"])
app_router = APIRouter(prefix="/api/remediation/mailbox", tags=["d7"])

EXECUTOR_RATE_LIMIT = "120/minute"
CALIBRATION_RATE_LIMIT = "30/minute"


def _owner_policy(db: Session, api_key: ApiKey, mailbox: str):
    policy = S.get_policy(db, api_key.account_id)
    if (policy is None or policy.owner_user_id != api_key.user_id or not policy.mailbox_address
            or policy.mailbox_address.lower() != mailbox.strip().lower()):
        raise HTTPException(status_code=403, detail="Auto-quarantine is set up for a different user or mailbox.")
    return policy


def _protocol(fn):
    try:
        return fn()
    except S.D7Error as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


# ---- the add-on's loop ------------------------------------------------------------------------


@v1_router.post("/inbound", response_model=D7InboundResponse)
@limiter.limit(API_KEY_ANALYZE_RATE_LIMIT, key_func=api_key_rate_limit_key)
def inbound(request: Request, payload: D7InboundRequest, db: Session = Depends(get_db),
            api_key: ApiKey = Depends(get_api_key)) -> D7InboundResponse:
    policy = _owner_policy(db, api_key, payload.mailbox)
    raw_bytes = _validated_raw_bytes(payload.raw_email)
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    existing, result = _lookup_or_run(db, api_key, raw_bytes, content_hash)
    if existing is not None:
        case = existing
    else:
        assert result is not None
        if public_verdict(result.verdict) == "clean":
            record_observation(db, api_key.account_id, content_hash, result.sender_signals, result.verdict.value)
            db.commit()
            return D7InboundResponse(verdict=result.verdict.value, score=result.score, case_id=None,
                                     gate=None, directive=None)
        user = db.get(User, api_key.user_id)
        subject = result.parsed.subject or "api-email"
        saved = persist_case_and_build_response(raw_bytes, subject[:200] + ".eml", result, user, db,
                                                content_hash=content_hash)
        case = db.get(Case, saved.id)

    # The add-on's fingerprint must describe this message's sender; the subject half is
    # re-checked by the add-on itself against the live message before it acts.
    if (case.from_addr or "").strip().lower() != payload.from_addr.strip().lower():
        db.commit()
        raise HTTPException(status_code=422, detail="from_addr does not match the analyzed message.")

    gate, directive, withheld = S.decide_and_maybe_issue(
        db, case=case, policy=policy, mailbox=payload.mailbox.strip().lower(),
        gmail_message_id=payload.gmail_message_id, fingerprint=payload.fingerprint,
    )
    db.commit()
    return D7InboundResponse(verdict=case.verdict, score=case.score, case_id=str(case.id),
                             gate=gate.as_dict(), directive=directive, withheld=withheld)


@v1_router.post("/directives/{action_id}/claim")
@limiter.limit(EXECUTOR_RATE_LIMIT, key_func=api_key_rate_limit_key)
def claim(request: Request, action_id: uuid.UUID, payload: D7ClaimRequest, db: Session = Depends(get_db),
          api_key: ApiKey = Depends(get_api_key)) -> dict:
    d = payload.directive.model_dump()
    if d["id"] != str(action_id):
        raise HTTPException(status_code=409, detail="Directive id does not match the URL.")
    out = _protocol(lambda: S.claim(db, api_key.account_id, d))
    db.commit()
    return out


@v1_router.post("/directives/{action_id}/result")
@limiter.limit(EXECUTOR_RATE_LIMIT, key_func=api_key_rate_limit_key)
def result(request: Request, action_id: uuid.UUID, payload: D7ResultRequest, db: Session = Depends(get_db),
           api_key: ApiKey = Depends(get_api_key)) -> dict:
    d = payload.directive.model_dump()
    if d["id"] != str(action_id):
        raise HTTPException(status_code=409, detail="Directive id does not match the URL.")
    out = _protocol(lambda: S.report_result(db, api_key.account_id, d, payload.status, payload.detail))
    db.commit()
    return out


@v1_router.get("/pending")
@limiter.limit(EXECUTOR_RATE_LIMIT, key_func=api_key_rate_limit_key)
def pending(request: Request, mailbox: str, db: Session = Depends(get_db),
            api_key: ApiKey = Depends(get_api_key)) -> dict:
    _owner_policy(db, api_key, mailbox)
    out = S.pending_for_executor(db, api_key.account_id)
    db.commit()
    return out


@v1_router.post("/undo")
@limiter.limit(EXECUTOR_RATE_LIMIT, key_func=api_key_rate_limit_key)
def addon_undo(request: Request, payload: D7AddonUndoRequest, db: Session = Depends(get_db),
               api_key: ApiKey = Depends(get_api_key)) -> dict:
    """The add-on card's "Undo / Not phishing" on an open quarantined message."""
    _owner_policy(db, api_key, payload.mailbox)
    move = S.find_executed_move(db, api_key.account_id, payload.gmail_message_id)
    if move is None:
        raise HTTPException(status_code=404, detail="Cordon has no completed move for this message.")
    user = db.get(User, api_key.user_id)
    d = _protocol(lambda: S.request_undo(db, move, source="addon", actor=user.email if user else "addon"))
    db.commit()
    return {"directive": d}


@v1_router.post("/manual-restore")
@limiter.limit(EXECUTOR_RATE_LIMIT, key_func=api_key_rate_limit_key)
def manual_restore(request: Request, payload: D7ManualRestoreRequest, db: Session = Depends(get_db),
                   api_key: ApiKey = Depends(get_api_key)) -> dict:
    _owner_policy(db, api_key, payload.mailbox)
    ok = S.record_manual_restore(db, api_key.account_id, payload.action_id, payload.gmail_message_id)
    db.commit()
    return {"recorded": ok}


@v1_router.post("/calibration")
@limiter.limit(CALIBRATION_RATE_LIMIT, key_func=api_key_rate_limit_key)
def calibration_start(request: Request, payload: D7CalibrationStartRequest, db: Session = Depends(get_db),
                      api_key: ApiKey = Depends(get_api_key)) -> dict:
    policy = _owner_policy(db, api_key, payload.mailbox)
    run = CAL.start(db, policy)
    log_event(db, event_type="d7_calibration_started", account_id=api_key.account_id,
              user_id=api_key.user_id, detail={"run_id": str(run.id), "floor": run.score_floor})
    db.commit()
    return {"run_id": str(run.id), "score_floor": run.score_floor}


def _own_run(db: Session, account_id, run_id: uuid.UUID) -> CalibrationRun:
    run = db.get(CalibrationRun, run_id)
    if run is None or run.account_id != account_id:
        raise HTTPException(status_code=404, detail="Calibration run not found.")
    return run


@v1_router.post("/calibration/{run_id}/batch")
@limiter.limit(CALIBRATION_RATE_LIMIT, key_func=api_key_rate_limit_key)
def calibration_batch(request: Request, run_id: uuid.UUID, payload: D7CalibrationBatchRequest,
                      db: Session = Depends(get_db), api_key: ApiKey = Depends(get_api_key)) -> dict:
    _owner_policy(db, api_key, payload.mailbox)
    run = _own_run(db, api_key.account_id, run_id)
    msgs = [(_validated_raw_bytes(m.raw_email), m.gmail_message_id, m.received_at) for m in payload.messages]
    try:
        rows = CAL.add_batch(db, run, msgs)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    db.commit()
    return {"added": len(rows), "would_move": sum(1 for r in rows if r.get("would_move")),
            "total": len(run.rows or [])}


@v1_router.post("/calibration/{run_id}/complete")
@limiter.limit(CALIBRATION_RATE_LIMIT, key_func=api_key_rate_limit_key)
def calibration_complete(request: Request, run_id: uuid.UUID, payload: D7CalibrationStartRequest,
                         db: Session = Depends(get_db), api_key: ApiKey = Depends(get_api_key)) -> dict:
    policy = _owner_policy(db, api_key, payload.mailbox)
    run = _own_run(db, api_key.account_id, run_id)
    if run.status != "running":
        raise HTTPException(status_code=409, detail="This calibration run is already complete.")
    CAL.complete(db, run, policy)
    summary = CAL.summarize(run)
    log_event(db, event_type="d7_calibration_completed", account_id=api_key.account_id,
              user_id=api_key.user_id, detail=summary)
    db.commit()
    return summary


# ---- the owner's app routes -------------------------------------------------------------------


def _action_dict(row: MailboxAction, case: Case | None = None) -> dict:
    return {
        "id": str(row.id), "kind": row.kind, "status": row.status, "case_id": str(row.case_id) if row.case_id else None,
        "parent_id": str(row.parent_id) if row.parent_id else None,
        "gmail_message_id": row.gmail_message_id, "label": row.label, "gate": row.gate,
        "issued_at": row.issued_at.isoformat() if row.issued_at else None,
        "executed_at": row.executed_at.isoformat() if row.executed_at else None,
        "undone_at": row.undone_at.isoformat() if row.undone_at else None,
        "undo_source": row.undo_source, "detail": row.detail, "actor": row.actor,
        "from_addr": case.from_addr if case else None, "subject": case.subject if case else None,
    }


def _state(db: Session, account_id) -> dict:
    now = S.utcnow()
    policy = S.get_policy(db, account_id)
    actions = (
        db.query(MailboxAction).filter(MailboxAction.account_id == account_id)
        .order_by(MailboxAction.issued_at.desc()).limit(30).all()
    )
    cases = {c.id: c for c in db.query(Case).filter(Case.id.in_([a.case_id for a in actions if a.case_id])).all()} \
        if actions else {}
    feedback = (
        db.query(RuleFeedback.indicator_id, func.count(RuleFeedback.id))
        .filter(RuleFeedback.account_id == account_id)
        .group_by(RuleFeedback.indicator_id).all()
    )
    out = {
        "policy": None,
        "server": {"secret_set": bool(settings.d7_directive_secret), "label": settings.d7_quarantine_label,
                   "calibration_max_age_days": settings.d7_calibration_max_age_days},
        "calibration": CAL.summarize(_latest_run(db, account_id)),
        "actions": [_action_dict(a, cases.get(a.case_id)) for a in actions],
        "feedback": sorted(({"indicator_id": i, "false_positives": n} for i, n in feedback),
                           key=lambda r: -r["false_positives"]),
        "kill_switch": S.kill_switch_on(db, account_id),
    }
    if policy is not None:
        out["policy"] = {
            "enabled": policy.enabled, "mailbox_address": policy.mailbox_address,
            "owner_user_id": str(policy.owner_user_id) if policy.owner_user_id else None,
            "score_floor": policy.score_floor, "max_moves_per_hour": policy.max_moves_per_hour,
            "notify_email": policy.notify_email,
            "calibrated_at": policy.calibrated_at.isoformat() if policy.calibrated_at else None,
            "calibrated_floor": policy.calibrated_floor,
            "halted_at": policy.halted_at.isoformat() if policy.halted_at else None,
            "halt_reason": policy.halt_reason,
            "mailbox_allowlisted": S.mailbox_allowlisted(policy.mailbox_address),
            "enable_blockers": S.enable_blockers(policy, now),
            "moves_last_hour": S.moves_in_window(db, account_id, now),
        }
    return out


def _latest_run(db: Session, account_id):  # the latest run, complete or still running
    return S.latest_calibration(db, account_id, complete=False)


@app_router.get("")
def get_state(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    return _state(db, user.account_id)


@app_router.put("")
def update_policy(payload: D7PolicyUpdate, db: Session = Depends(get_db), user: User = Depends(require_admin)) -> dict:
    policy = S.ensure_policy(db, user.account_id)
    changes = payload.model_dump(exclude_none=True)
    if "mailbox_address" in changes:
        mailbox = changes["mailbox_address"].strip().lower()
        if mailbox != (policy.mailbox_address or ""):
            # A new mailbox is a new owner binding: off until calibrated for it.
            policy.mailbox_address, policy.owner_user_id = mailbox, user.id
            policy.enabled, policy.calibrated_at, policy.calibrated_floor = False, None, None
    for k in ("score_floor", "max_moves_per_hour", "notify_email"):
        if k in changes:
            setattr(policy, k, changes[k])
    if policy.enabled and not S.calibration_covers(policy, S.utcnow())[0]:
        policy.enabled = False  # lowered the floor below the calibrated one: recalibrate first
    log_event(db, event_type="d7_policy_updated", account_id=user.account_id, user_id=user.id, detail=changes)
    db.commit()
    return _state(db, user.account_id)


@app_router.post("/enable")
def enable(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> dict:
    policy = S.ensure_policy(db, user.account_id)
    if policy.owner_user_id != user.id:
        raise HTTPException(status_code=403, detail="Only the mailbox owner can enable auto-quarantine.")
    blockers = S.enable_blockers(policy, S.utcnow())
    if blockers:
        raise HTTPException(status_code=409, detail=" ".join(blockers))
    policy.enabled = True
    log_event(db, event_type="d7_enabled", account_id=user.account_id, user_id=user.id,
              detail={"floor": policy.score_floor, "max_moves_per_hour": policy.max_moves_per_hour})
    db.commit()
    return _state(db, user.account_id)


@app_router.post("/disable")
def disable(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> dict:
    policy = S.ensure_policy(db, user.account_id)
    policy.enabled = False
    log_event(db, event_type="d7_disabled", account_id=user.account_id, user_id=user.id)
    db.commit()
    return _state(db, user.account_id)


@app_router.post("/resume")
def resume(db: Session = Depends(get_db), user: User = Depends(require_admin)) -> dict:
    policy = S.ensure_policy(db, user.account_id)
    policy.halted_at, policy.halt_reason = None, None
    log_event(db, event_type="d7_resumed", account_id=user.account_id, user_id=user.id)
    db.commit()
    return _state(db, user.account_id)


@app_router.get("/calibration")
def calibration_report(db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    run = _latest_run(db, user.account_id)
    return {"summary": CAL.summarize(run), "rows": (run.rows if run else [])}


@app_router.get("/cases/{case_id}")
def case_actions(case_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    rows = (
        db.query(MailboxAction)
        .filter(MailboxAction.account_id == user.account_id, MailboxAction.case_id == case_id)
        .order_by(MailboxAction.issued_at.desc()).all()
    )
    return {"actions": [_action_dict(r) for r in rows]}


@app_router.post("/actions/{action_id}/undo")
def app_undo(action_id: uuid.UUID, db: Session = Depends(get_db), user: User = Depends(get_current_user)) -> dict:
    move = db.get(MailboxAction, action_id)
    if move is None or move.account_id != user.account_id:
        raise HTTPException(status_code=404, detail="Action not found.")
    _protocol(lambda: S.request_undo(db, move, source="app", actor=user.email))
    db.commit()
    return {"queued": True, "detail": "The Gmail add-on restores it on its next run (within about 5 minutes)."}
