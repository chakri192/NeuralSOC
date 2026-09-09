"""Read access to the audit log (api/audit.py's record_audit_event() is
the only writer). Admin-only, tenant-scoped, cursor-paginated the same
way api/routes/alerts.py's GET /alerts is.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api import models
from api.database import get_db
from api.deps import limiter, require_scope, scope_to_tenant

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


class AuditLogEntry(BaseModel):
    id: int
    tenant_id: Optional[int] = None
    actor_user_id: Optional[int] = None
    actor_label: Optional[str] = None
    action: str
    target: Optional[str] = None
    detail: Optional[str] = None
    ip_address: Optional[str] = None
    created_at: str = ""


@router.get("", response_model=List[AuditLogEntry])
@limiter.limit("60/minute")
def list_audit_log(
    request: Request,
    cursor: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("users:manage")),
):
    """require_scope("users:manage") -- the same scope that gates
    inviting/deactivating teammates and minting sensor tokens, since
    reading who-did-what is the same trust level as managing the tenant
    itself. scope_to_tenant() means the static service key (no
    tenant_id) can still see every tenant's log, matching every other
    route's documented behavior for that credential."""
    query = scope_to_tenant(db.query(models.AuditLog), principal, models.AuditLog)
    if cursor > 0:
        query = query.filter(models.AuditLog.id < cursor)
    rows = query.order_by(models.AuditLog.id.desc()).limit(limit).all()
    return [
        AuditLogEntry(
            id=r.id,
            tenant_id=r.tenant_id,
            actor_user_id=r.actor_user_id,
            actor_label=r.actor_label,
            action=r.action,
            target=r.target,
            detail=r.detail,
            ip_address=r.ip_address,
            created_at=r.created_at.isoformat() if r.created_at else "",
        )
        for r in rows
    ]
