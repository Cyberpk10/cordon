"""Closed-loop remediation (a recommended, human-approved playbook) for cases and
incidents, plus per-recipient targeted-training aggregation — M4 Stage 3, extended for
incidents in M5 Stage 1.

Aegis only ever recommends and records operator decisions here. Nothing in this module
(or app.remediation.playbook / app.remediation.intrusion_playbook / app.remediation.targets)
blocks a sender, resets a credential, quarantines a message, isolates a host, blocks an IP,
or notifies anyone automatically — there is no network/SMTP/subprocess call anywhere in this
feature. POST .../action's only effect is inserting a state row; GET /api/targets's only
write is upserting the stored training recommendation it computed from data already in the
database.

M6 Stage 1 used to add one side effect to the two playbook-fetch endpoints below: an
autonomy evaluation that could auto-execute a mailbox/identity action through a connector
(including the real Microsoft Graph one). D5 retired that path: Cordon no longer writes to a
mailbox automatically at any tier (it needs mailbox write scopes and CASA verification, the
next rung). Automatic actions now come only from the D5 engine (app.autonomy.runner), which
acts on Cordon's own records and proposes mailbox remediation for a human to carry out.
Fetching a playbook has no side effect beyond reading.

Requires auth; every query/write in this file is scoped to the authenticated user's own
account_id (M8 Stage 2) — a case/incident belonging to another account resolves to 404.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.core.config import settings
from app.db.models import (
    Case,
    Incident,
    RemediationAction,
    TrainingRecommendation,
    User,
)
from app.db.session import get_db
from app.models.schemas import (
    PlaybookStepResponse,
    RemediationActionRequest,
    RemediationActionResponse,
    RemediationControlRef,
    RemediationPlaybookResponse,
    RemediationStatus,
    TargetSummaryResponse,
    TargetsListResponse,
)
from app.remediation.intrusion_playbook import generate_intrusion_playbook
from app.remediation.playbook import PlaybookStep, generate_playbook
from app.remediation.targets import TargetCaseRow, aggregate_targets

cases_router = APIRouter(prefix="/api/cases", tags=["remediation"])
incidents_router = APIRouter(prefix="/api/incidents", tags=["remediation"])
targets_router = APIRouter(prefix="/api/targets", tags=["targets"])


def _latest_actions_by_step(
    db: Session, *, case_id: UUID | None = None, incident_id: UUID | None = None
) -> dict[str, RemediationAction]:
    # Ordered by step_id, then created_at desc: the first row seen per step_id is that
    # step's latest action — same pattern as labels.py/dashboard.py/audit.py. Exactly one
    # of case_id/incident_id is passed by callers (mirrors the Label/RemediationAction
    # dual-parent-FK CHECK constraint).
    query = db.query(RemediationAction)
    query = (
        query.filter(RemediationAction.case_id == case_id)
        if case_id is not None
        else query.filter(RemediationAction.incident_id == incident_id)
    )
    latest: dict[str, RemediationAction] = {}
    rows = query.order_by(RemediationAction.step_id, RemediationAction.created_at.desc()).all()
    for row in rows:
        latest.setdefault(row.step_id, row)
    return latest


def _control_refs_for_step(
    framework_mappings: dict, related_indicator_ids: list[str]
) -> list[RemediationControlRef]:
    seen: set[tuple[str, str]] = set()
    refs: list[RemediationControlRef] = []
    for framework_key, control_refs in framework_mappings.items():
        for ref in control_refs:
            if ref["indicator_id"] not in related_indicator_ids:
                continue
            key = (framework_key, ref["control_id"])
            if key in seen:
                continue
            seen.add(key)
            refs.append(
                RemediationControlRef(
                    framework_key=framework_key,
                    control_id=ref["control_id"],
                    control_name=ref["control_name"],
                )
            )
    return refs


def _build_playbook_response_generic(
    *,
    entity_id: UUID,
    framework_mappings: dict,
    steps: list[PlaybookStep],
    latest_actions: dict[str, RemediationAction],
) -> RemediationPlaybookResponse:
    step_responses = [
        PlaybookStepResponse(
            step_id=step.step_id,
            title=step.title,
            description=step.description,
            category=step.category,
            related_indicator_ids=step.related_indicator_ids,
            control_refs=_control_refs_for_step(framework_mappings, step.related_indicator_ids),
            status=RemediationStatus(action.status) if (action := latest_actions.get(step.step_id))
            else RemediationStatus.RECOMMENDED,
            actor=action.actor if action else None,
            note=action.note if action else None,
            acted_at=action.created_at if action else None,
        )
        for step in steps
    ]

    return RemediationPlaybookResponse(
        case_id=entity_id, generated_at=datetime.utcnow(), steps=step_responses
    )


def _build_playbook_response(case: Case, db: Session) -> RemediationPlaybookResponse:
    indicator_ids = [i["id"] for i in case.indicators]
    steps = generate_playbook(indicator_ids)
    latest_actions = _latest_actions_by_step(db, case_id=case.id)
    return _build_playbook_response_generic(
        entity_id=case.id,
        framework_mappings=case.framework_mappings,
        steps=steps,
        latest_actions=latest_actions,
    )


def _build_incident_playbook_response(incident: Incident, db: Session) -> RemediationPlaybookResponse:
    finding_ids = [f["id"] for f in incident.findings]
    steps = generate_intrusion_playbook(finding_ids)
    latest_actions = _latest_actions_by_step(db, incident_id=incident.id)
    return _build_playbook_response_generic(
        entity_id=incident.id,
        framework_mappings=incident.framework_mappings,
        steps=steps,
        latest_actions=latest_actions,
    )


@cases_router.post("/{case_id}/remediate", response_model=RemediationPlaybookResponse)
async def get_case_remediation_playbook(
    case_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationPlaybookResponse:
    """Derives the playbook from the case's already-stored indicators and merges in
    whatever approval state already exists — the returned playbook itself is unaffected by
    autonomy either way. Also (M6 Stage 1) idempotently runs autonomy policy evaluation for
    any indicator with a mapped autonomy action; safe to call repeatedly — an action type
    already evaluated for this case is never re-evaluated or re-executed."""
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")

    return _build_playbook_response(case, db)


@incidents_router.post("/{incident_id}/remediate", response_model=RemediationPlaybookResponse)
async def get_incident_remediation_playbook(
    incident_id: UUID,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationPlaybookResponse:
    """Incident-scoped equivalent of get_case_remediation_playbook, including the same
    idempotent M6 Stage 1 autonomy evaluation side effect."""
    incident = db.get(Incident, incident_id)
    if incident is None or incident.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Incident not found.")

    return _build_incident_playbook_response(incident, db)


@cases_router.post(
    "/{case_id}/remediate/{step_id}/action", response_model=RemediationActionResponse
)
async def record_remediation_action(
    case_id: UUID,
    step_id: str,
    body: RemediationActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationActionResponse:
    """Records that an operator approved or completed a step. This is the only write in
    the whole feature, and all it writes is state — it does not perform the step."""
    case = db.get(Case, case_id)
    if case is None or case.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Case not found.")

    indicator_ids = [i["id"] for i in case.indicators]
    applicable_step_ids = {step.step_id for step in generate_playbook(indicator_ids)}
    if step_id not in applicable_step_ids:
        raise HTTPException(
            status_code=400, detail=f"'{step_id}' is not a recommended step for this case."
        )

    action = RemediationAction(
        account_id=current_user.account_id,
        case_id=case_id,
        step_id=step_id,
        status=body.status,
        actor=current_user.email,
        note=body.note,
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    return RemediationActionResponse(
        id=action.id,
        case_id=action.case_id,
        step_id=action.step_id,
        status=action.status,
        actor=action.actor,
        note=action.note,
        created_at=action.created_at,
    )


@incidents_router.post(
    "/{incident_id}/remediate/{step_id}/action", response_model=RemediationActionResponse
)
async def record_incident_remediation_action(
    incident_id: UUID,
    step_id: str,
    body: RemediationActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> RemediationActionResponse:
    """Incident-scoped equivalent of record_remediation_action. This is the only write in
    the whole feature, and all it writes is state — it does not perform the step (no host
    is isolated, no IP is blocked, no credential is rotated)."""
    incident = db.get(Incident, incident_id)
    if incident is None or incident.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Incident not found.")

    finding_ids = [f["id"] for f in incident.findings]
    applicable_step_ids = {step.step_id for step in generate_intrusion_playbook(finding_ids)}
    if step_id not in applicable_step_ids:
        raise HTTPException(
            status_code=400, detail=f"'{step_id}' is not a recommended step for this incident."
        )

    action = RemediationAction(
        account_id=current_user.account_id,
        incident_id=incident_id,
        step_id=step_id,
        status=body.status,
        actor=current_user.email,
        note=body.note,
    )
    db.add(action)
    db.commit()
    db.refresh(action)

    return RemediationActionResponse(
        id=action.id,
        incident_id=action.incident_id,
        step_id=action.step_id,
        status=action.status,
        actor=action.actor,
        note=action.note,
        created_at=action.created_at,
    )


@targets_router.get("", response_model=TargetsListResponse)
async def get_targets(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> TargetsListResponse:
    """Live aggregation over every non-safe case's recipients. For any recipient
    currently at/above the threshold, upserts the stored TrainingRecommendation row
    (idempotent — rewriting the same derived state is not a destructive action)."""
    cases_orm = (
        db.query(Case)
        .filter(Case.account_id == current_user.account_id, Case.verdict != "safe")
        .all()
    )
    case_rows = [
        TargetCaseRow(
            id=str(case.id),
            created_at=case.created_at,
            verdict=case.verdict,
            to_addresses=case.to_addresses,
            indicators=case.indicators,
        )
        for case in cases_orm
    ]
    summaries = aggregate_targets(case_rows, settings.target_training_threshold)

    responses: list[TargetSummaryResponse] = []
    for summary in summaries:
        first_flagged_at = None
        if summary.flagged_for_training:
            existing = (
                db.query(TrainingRecommendation)
                .filter(
                    TrainingRecommendation.account_id == current_user.account_id,
                    TrainingRecommendation.recipient == summary.recipient,
                )
                .first()
            )
            now = datetime.now(timezone.utc)
            if existing:
                existing.hit_count = summary.hit_count
                existing.top_indicator_id = summary.top_indicator_id
                existing.top_indicator_title = summary.top_indicator_title
                existing.recommendation = summary.recommendation
                existing.updated_at = now
                first_flagged_at = existing.first_flagged_at
            else:
                new_row = TrainingRecommendation(
                    account_id=current_user.account_id,
                    recipient=summary.recipient,
                    hit_count=summary.hit_count,
                    top_indicator_id=summary.top_indicator_id,
                    top_indicator_title=summary.top_indicator_title,
                    recommendation=summary.recommendation,
                )
                db.add(new_row)
                db.flush()
                first_flagged_at = new_row.first_flagged_at

        responses.append(
            TargetSummaryResponse(
                recipient=summary.recipient,
                hit_count=summary.hit_count,
                flagged_for_training=summary.flagged_for_training,
                top_indicator_id=summary.top_indicator_id,
                top_indicator_title=summary.top_indicator_title,
                recommendation=summary.recommendation,
                sample_case_ids=summary.sample_case_ids,
                first_flagged_at=first_flagged_at,
            )
        )

    db.commit()

    return TargetsListResponse(threshold=settings.target_training_threshold, targets=responses)
