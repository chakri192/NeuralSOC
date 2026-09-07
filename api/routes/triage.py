"""Incident triage state -- replaces shared/triage_store.py's local
SQLite table (never shared across dashboard/console processes or
machines, and its "actor" was a free-text string nothing verified).
Every write's actor is the authenticated caller's own user_id; every
read/write is scoped to the caller's own tenant via scope_to_tenant().
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.database import get_db
from api.deps import require_scope, scope_to_tenant
from api.models import TRIAGE_OPEN, VALID_TRIAGE_STATUSES, IncidentTriage

router = APIRouter(prefix="/api/v1/triage", tags=["triage"])

_DEFAULT_STATUS = {"status": TRIAGE_OPEN, "note": "", "actor": "", "updated_at": ""}


class TriageUpdateRequest(BaseModel):
    status: str
    note: Optional[str] = ""


def _serialize(row: IncidentTriage) -> dict:
    return {
        "status": row.status,
        "note": row.note or "",
        "actor": row.actor.email if row.actor else "",
        "updated_at": row.updated_at.isoformat() if row.updated_at else "",
    }


@router.get("")
def get_all_statuses(db: Session = Depends(get_db), principal: dict = Depends(require_scope("alerts:read"))):
    """Bulk read for rendering a whole incident queue without one query
    per row -- same shape shared/triage_store.py's own get_all_statuses()
    returned, so dashboard/terminal call sites barely change."""
    query = scope_to_tenant(db.query(IncidentTriage), principal, IncidentTriage)
    return {row.incident_id: _serialize(row) for row in query.all()}


@router.get("/{incident_id}")
def get_status(
    incident_id: str,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("alerts:read")),
):
    query = scope_to_tenant(db.query(IncidentTriage), principal, IncidentTriage)
    row = query.filter(IncidentTriage.incident_id == incident_id).first()
    return _serialize(row) if row else dict(_DEFAULT_STATUS)


@router.post("/{incident_id}")
def set_status(
    incident_id: str,
    body: TriageUpdateRequest,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("triage:write")),
):
    if body.status not in VALID_TRIAGE_STATUSES:
        raise HTTPException(status_code=422, detail=f"Invalid triage status: {body.status!r}")

    tenant_id = principal.get("tenant_id")
    if tenant_id is None:
        # The static service key holds every scope but represents no one
        # in particular -- "who triaged this" is meaningless for it.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Triage actions require a per-employee session, not the static service key",
        )
    user_id = principal.get("user_id")

    row = (
        db.query(IncidentTriage)
        .filter(IncidentTriage.tenant_id == tenant_id, IncidentTriage.incident_id == incident_id)
        .first()
    )
    if row:
        row.status = body.status
        row.note = body.note
        row.actor_user_id = user_id
    else:
        row = IncidentTriage(
            tenant_id=tenant_id, incident_id=incident_id, status=body.status, note=body.note, actor_user_id=user_id
        )
        db.add(row)
    db.commit()
    db.refresh(row)
    return _serialize(row)
