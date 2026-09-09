"""Audit logging: who did what, when, per tenant. record_audit_event()
is the one writer every route below calls; GET /api/v1/audit
(api/routes/audit.py) is the one reader.

Best-effort by design, like api/deps.py's revocation/lockout checks: an
audit-log write failure (a transient DB hiccup) must never fail the
underlying request it's describing -- the action itself (a login, a
triage update) already succeeded or failed on its own merits before
this is ever called.
"""
import logging

from sqlalchemy.orm import Session

from api.models import AuditLog

logger = logging.getLogger(__name__)


def record_audit_event(
    db: Session,
    action: str,
    tenant_id: int = None,
    actor_user_id: int = None,
    actor_label: str = None,
    target: str = None,
    detail: str = None,
    ip_address: str = None,
) -> None:
    try:
        db.add(
            AuditLog(
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                actor_label=actor_label,
                action=action,
                target=target,
                detail=detail,
                ip_address=ip_address,
            )
        )
        db.commit()
    except Exception as ex:
        db.rollback()
        logger.error("Failed to record audit event action=%s target=%s: %s", action, target, ex)
