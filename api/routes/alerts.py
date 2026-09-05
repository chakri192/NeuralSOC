"""Alert routes: cursor-paginated listing and single-alert lookup."""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from api import models
from api.deps import get_authenticated_db, limiter, require_scope
from api.schemas import AlertResponse

router = APIRouter(prefix="/api/v1")


@router.get("/alerts", response_model=List[AlertResponse])
@limiter.limit("100/minute")
def get_alerts(
    request: Request,
    cursor: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=100),  # server-side cap
    db: Session = Depends(get_authenticated_db),
    _scope: dict = Depends(require_scope("alerts:read")),
):
    # No defer() on evidence here: with it deferred but still read by the
    # response model, Pydantic's attribute access triggers a lazy load per
    # row — up to 100 extra SELECTs per request. Loading it in the one query
    # up front is strictly fewer round-trips for this page size.
    query = db.query(models.Alert)
    if cursor > 0:
        query = query.filter(models.Alert.id < cursor)
    return query.order_by(models.Alert.id.desc()).limit(limit).all()


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
@limiter.limit("100/minute")
def get_alert_by_id(
    request: Request,
    alert_id: str,
    db: Session = Depends(get_authenticated_db),
    _scope: dict = Depends(require_scope("alerts:read")),
):
    alert = db.query(models.Alert).filter(models.Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return alert
