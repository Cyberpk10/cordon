"""In-app notifications (D5): written by the autonomy engine's NOTIFY action and by L3
mailbox recommendations awaiting approval. Account-scoped; retracted notifications (their
action was undone) are hidden."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.auth.dependencies import get_current_user
from app.db.models import Notification, User
from app.db.session import get_db
from app.models.schemas import NotificationListResponse, NotificationResponse

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


def _visible(db: Session, account_id: UUID):
    return db.query(Notification).filter(
        Notification.account_id == account_id, Notification.retracted_at.is_(None)
    )


@router.get("", response_model=NotificationListResponse)
async def list_notifications(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> NotificationListResponse:
    q = _visible(db, current_user.account_id)
    unread = q.filter(Notification.read_at.is_(None)).count()
    rows = q.order_by(Notification.created_at.desc()).limit(limit).all()
    return NotificationListResponse(items=[NotificationResponse.model_validate(r) for r in rows], unread=unread)


@router.post("/read-all", response_model=NotificationListResponse)
async def read_all(
    db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> NotificationListResponse:
    now = datetime.now(timezone.utc)
    _visible(db, current_user.account_id).filter(Notification.read_at.is_(None)).update(
        {"read_at": now}, synchronize_session=False
    )
    db.commit()
    return await list_notifications(limit=20, db=db, current_user=current_user)


@router.post("/{notification_id}/read", response_model=NotificationResponse)
async def read_one(
    notification_id: UUID, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)
) -> NotificationResponse:
    row = db.get(Notification, notification_id)
    if row is None or row.account_id != current_user.account_id:
        raise HTTPException(status_code=404, detail="Notification not found.")
    if row.read_at is None:
        row.read_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(row)
    return NotificationResponse.model_validate(row)
