"""Tenant-scoped alert ingestion: the boundary a tenant's own on-prem
collector authenticates against with a per-tenant sensor token (see
api/models.py's SensorToken) instead of the single blanket
TSOC_API_KEY -- so a compromised sensor at Tenant A can never write
data tagged as Tenant B.

Deliberately a separate credential type from api/deps.py's
verify_auth/require_scope (employee JWTs and the static service key):
a sensor identifies a *collector*, not a person, carries no scopes, and
is authenticated purely by hashed-token lookup against SensorToken.
"""
import hashlib
import secrets
from datetime import datetime, timezone
import logging
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import bindparam, insert, update
from sqlalchemy.orm import Session

from api.audit import record_audit_event
from api.database import get_db
from api.deps import get_remote_address, limiter, require_scope
from api.models import Alert, SensorToken
from api.schemas import AlertPayload

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def require_sensor_token(request: Request, db: Session = Depends(get_db)) -> SensorToken:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing sensor token")
    token = auth[7:].strip()
    sensor = (
        db.query(SensorToken)
        .filter(SensorToken.token_hash == _hash_token(token), SensorToken.is_active.is_(True))
        .first()
    )
    if not sensor:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or inactive sensor token")
    sensor.last_used_at = datetime.now(timezone.utc)
    db.commit()
    return sensor


def bulk_upsert_alerts(db: Session, tenant_id: int, alert_dicts: List[dict]) -> None:
    """Same insert-or-update-in-bulk strategy api/kafka_sink.py used
    while it wrote to Postgres directly -- this endpoint is now the
    single place that does. Stamps tenant_id onto every row itself;
    never trusts a client-supplied tenant_id in the payload (the sensor
    token IS the tenant -- that's the entire point of this boundary).

    The "does this alert already exist" lookup below is scoped to this
    same tenant_id, not a bare alert_id match -- alert_id only has a
    global UNIQUE constraint (api/models.py), not a (tenant_id,
    alert_id) one, so an unscoped lookup would let one tenant's sensor
    silently overwrite (and reassign the tenant_id of) another tenant's
    existing alert row just by sending a colliding alert_id. Scoped this
    way, a genuine cross-tenant collision instead fails the INSERT on
    the DB's own unique constraint and gets DLQ'd by the per-item
    fallback below -- data loss for that one alert, never a silent
    cross-tenant hijack.
    """
    for d in alert_dicts:
        d["tenant_id"] = tenant_id
    aids = [d["alert_id"] for d in alert_dicts]
    existing_aids = {
        row[0]
        for row in db.query(Alert.alert_id).filter(Alert.alert_id.in_(aids), Alert.tenant_id == tenant_id).all()
    }
    to_insert = [d for d in alert_dicts if d["alert_id"] not in existing_aids]
    to_update = [d for d in alert_dicts if d["alert_id"] in existing_aids]
    if to_insert:
        db.execute(insert(Alert), to_insert)
    if to_update:
        update_dicts = [
            {**{k: v for k, v in d.items() if k != "alert_id"}, "_alert_id": d["alert_id"]}
            for d in to_update
        ]
        db.execute(update(Alert).where(Alert.alert_id == bindparam("_alert_id")), update_dicts)
    db.flush()


@router.post("/alerts", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("120/minute")
def ingest_alerts(
    request: Request,
    alerts: List[AlertPayload],
    db: Session = Depends(get_db),
    sensor: SensorToken = Depends(require_sensor_token),
):
    """Accepts a batch (a lone collector still just sends a list of one).
    Same bulk-then-per-item-fallback shape api/kafka_sink.py's own
    _bulk_upsert used: a batch that fails all-or-nothing (e.g. one row
    violating a DB-level constraint AlertPayload's validation didn't
    catch) falls back to processing each item individually so one bad
    row can't take an otherwise-healthy batch down with it. The response
    tells the caller exactly which alert_ids failed, so it can DLQ only
    those rather than the whole batch."""
    if not alerts:
        return {"accepted": 0, "failed": []}

    alert_dicts = [a.model_dump() for a in alerts]
    try:
        bulk_upsert_alerts(db, sensor.tenant_id, alert_dicts)
        db.commit()
        return {"accepted": len(alert_dicts), "failed": []}
    except Exception as bulk_err:
        logger.warning("Bulk ingest upsert failed (%s); falling back to per-item", bulk_err)
        db.rollback()
        failed = []
        accepted = 0
        for d in alert_dicts:
            d["tenant_id"] = sensor.tenant_id
            try:
                with db.begin_nested():
                    existing = (
                        db.query(Alert)
                        .filter(Alert.alert_id == d["alert_id"], Alert.tenant_id == sensor.tenant_id)
                        .first()
                    )
                    if existing:
                        for k, v in d.items():
                            setattr(existing, k, v)
                    else:
                        db.add(Alert(**d))
                    db.flush()
                accepted += 1
            except Exception as item_err:
                logger.error("Per-item ingest failed for %s: %s", d.get("alert_id"), item_err)
                failed.append({"alert_id": d.get("alert_id"), "error": str(item_err)})
        db.commit()
        return {"accepted": accepted, "failed": failed}


class SensorTokenCreateRequest(BaseModel):
    name: str


@router.post("/tenants/{tenant_id}/sensor-tokens", status_code=status.HTTP_201_CREATED)
def create_sensor_token(
    request: Request,
    tenant_id: int,
    body: SensorTokenCreateRequest,
    db: Session = Depends(get_db),
    principal: dict = Depends(require_scope("users:manage")),
):
    """Admin-only, same cross-tenant guard as api/routes/auth.py's
    invite_user: holding users:manage somewhere doesn't by itself prove
    the caller administers THIS tenant."""
    if principal.get("tenant_id") != tenant_id and "*" not in principal.get("scopes", []):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot manage another tenant's sensor tokens")

    token = secrets.token_urlsafe(32)
    sensor = SensorToken(tenant_id=tenant_id, token_hash=_hash_token(token), name=body.name)
    db.add(sensor)
    db.commit()
    db.refresh(sensor)

    record_audit_event(
        db, "sensor_token.created", tenant_id=tenant_id, actor_user_id=principal.get("user_id"),
        target=body.name, ip_address=get_remote_address(request),
    )
    # The only time the cleartext token is ever returned -- token_hash is
    # all that's stored, so a leaked database dump doesn't hand out live
    # ingest credentials the way storing the raw token would.
    return {"id": sensor.id, "name": sensor.name, "token": token}
