"""D7 one-shot calibration: which of the owner's recent messages WOULD have been moved at the
current gate. Replaces a shadow mode.

The add-on reads recent received mail (read-only) and sends it here in batches. Each message
runs the normal pipeline; a malicious one is then built as a Case and given the D4 rules
investigation and the rules D6 synthesis inside a SAVEPOINT that is always rolled back. Only
the CalibrationRun's metadata rows persist: no Case, no raw file, no sender observation, no
notification, no directive, and nothing touches the mailbox.

Known limit: rolled-back messages don't see each other, so a wave formed only by messages in
this backtest isn't detected (a wave against Cases Cordon already has is).
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from app.analysis.email_pipeline import run_email_pipeline
from app.api.routes.analyze import case_from_result
from app.db.models import CalibrationRun, Case, MailboxRemediationPolicy
from app.investigation.build import save_investigation
from app.orchestration.orchestrator import run_orchestration
from app.remediation_d7.gate import evaluate_gate
from app.remediation_d7.service import gate_for_case, utcnow
from app.sender_baseline.loader import baseline_lookup_for
from app.sender_history.loader import load_sender_history

MAX_ROWS = 500


def start(db: Session, policy: MailboxRemediationPolicy, now: datetime | None = None) -> CalibrationRun:
    run = CalibrationRun(id=uuid.uuid4(), account_id=policy.account_id, score_floor=policy.score_floor,
                         status="running", rows=[], started_at=now or utcnow())
    db.add(run)
    db.flush()
    return run


def _row(msg_id: str, received_at: str | None, from_addr, subject, verdict, score, rule_score, gate,
         existing_case_id=None) -> dict:
    d = gate.as_dict()
    return {
        "gmail_message_id": msg_id, "received_at": received_at,
        "from_addr": from_addr, "subject": (subject or "")[:80],
        "verdict": verdict, "score": score, "rule_score": rule_score,
        "checks": {c["id"]: c["ok"] for c in d["checks"]},
        "would_move": d["passed"], "reasons": d["reasons"],
        "existing_case_id": str(existing_case_id) if existing_case_id else None,
    }


def evaluate_message(db: Session, account_id: uuid.UUID, raw_bytes: bytes, floor: int, msg_id: str,
                     received_at: str | None) -> dict:
    content_hash = hashlib.sha256(raw_bytes).hexdigest()
    existing = (
        db.query(Case)
        .filter(Case.account_id == account_id, Case.content_hash == content_hash)
        .order_by(Case.created_at.desc())
        .first()
    )
    if existing is not None:
        gate = gate_for_case(db, existing, floor)
        return _row(msg_id, received_at, existing.from_addr, existing.subject, existing.verdict,
                    existing.score, gate.score, gate, existing.id)

    result = run_email_pipeline(
        raw_bytes, load_sender_history(db, account_id), baseline_lookup_for(db, account_id), use_llm=False,
    )
    parsed = result.parsed
    verdict = result.verdict.value
    if verdict != "malicious":
        gate = evaluate_gate(verdict=verdict, rule_score=result.score, synthesis=None, floor=floor)
        return _row(msg_id, received_at, parsed.from_address, parsed.subject, verdict, result.score,
                    result.score, gate)

    savepoint = db.begin_nested()
    try:
        case = case_from_result(case_id=uuid.uuid4(), account_id=account_id, filename="calibration.eml",
                                result=result, raw_email_path=None, content_hash=None)
        db.add(case)
        db.flush()
        inv = save_investigation(db, account_id, case=case, trigger="auto", use_llm=False)
        db.flush()
        record, _ = run_orchestration(db, case, use_llm=False, investigation=inv)
        gate = evaluate_gate(verdict=verdict, rule_score=result.score, synthesis=record["synthesis"], floor=floor)
    finally:
        savepoint.rollback()
    return _row(msg_id, received_at, parsed.from_address, parsed.subject, verdict, result.score,
                result.score, gate)


def add_batch(db: Session, run: CalibrationRun, messages: list[tuple[bytes, str, str | None]]) -> list[dict]:
    if run.status != "running":
        raise ValueError("This calibration run is already complete.")
    seen = {r["gmail_message_id"] for r in run.rows or []}
    rows = []
    for raw_bytes, msg_id, received_at in messages:
        if msg_id in seen or len(run.rows or []) + len(rows) >= MAX_ROWS:
            continue
        try:
            rows.append(evaluate_message(db, run.account_id, raw_bytes, run.score_floor, msg_id, received_at))
        except Exception:  # noqa: BLE001 - one unparseable message must not stop the backtest
            rows.append({"gmail_message_id": msg_id, "received_at": received_at, "error": "could_not_analyze",
                         "would_move": False})
        seen.add(msg_id)
    run.rows = list(run.rows or []) + rows
    return rows


def complete(db: Session, run: CalibrationRun, policy: MailboxRemediationPolicy, now: datetime | None = None) -> None:
    now = now or utcnow()
    run.status, run.completed_at = "complete", now
    policy.calibrated_at, policy.calibrated_floor = now, run.score_floor


def summarize(run: CalibrationRun | None) -> dict | None:
    if run is None:
        return None
    rows = run.rows or []
    near = [r for r in rows if r.get("verdict") == "malicious" and not r.get("would_move")
            and sum(1 for ok in (r.get("checks") or {}).values() if not ok) == 1]
    return {
        "id": str(run.id), "status": run.status, "score_floor": run.score_floor,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "total": len(rows), "would_move": sum(1 for r in rows if r.get("would_move")),
        "near_misses": len(near), "errors": sum(1 for r in rows if r.get("error")),
    }
