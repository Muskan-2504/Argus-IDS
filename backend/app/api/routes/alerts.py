"""Alert endpoints: list/inspect (any authenticated user) and triage (analyst+)."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, require_min_role
from app.crud import alert as alert_crud
from app.db.session import get_db
from app.models.enums import AlertStatus, Role, Severity
from app.schemas.alert import AlertRead, AlertStatusUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[AlertRead])
def list_alerts(
    db: DbSession,
    _user: CurrentUser,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    source_ip: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[AlertRead]:
    """List alerts, most recent first, with optional filters."""
    alerts = alert_crud.list_alerts(
        db, status=status, severity=severity, source_ip=source_ip, limit=limit, offset=offset
    )
    enrichment = alert_crud.enrichment_map(db, (a.source_ip for a in alerts))
    return [alert_crud.to_read(a, enrichment) for a in alerts]


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(alert_id: int, db: DbSession, _user: CurrentUser) -> AlertRead:
    alert = alert_crud.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found.")
    return alert_crud.to_read(alert, alert_crud.enrichment_map(db, [alert.source_ip]))


@router.patch("/{alert_id}/status", response_model=AlertRead)
def update_alert_status(
    alert_id: int,
    payload: AlertStatusUpdate,
    db: DbSession,
    _user: Annotated[object, Depends(require_min_role(Role.analyst))],
) -> AlertRead:
    """Triage an alert: acknowledge, resolve, or mark as a false positive."""
    alert = alert_crud.get_alert(db, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Alert not found.")
    updated = alert_crud.update_status(db, alert, payload.status)
    return AlertRead.model_validate(updated)
