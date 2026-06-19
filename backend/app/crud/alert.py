"""Alert queries and triage updates."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.enums import AlertStatus, Severity


def get_alert(db: Session, alert_id: int) -> Alert | None:
    return db.get(Alert, alert_id)


def list_alerts(
    db: Session,
    *,
    status: AlertStatus | None = None,
    severity: Severity | None = None,
    source_ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Alert]:
    """Most-recent-first alerts, optionally filtered."""
    stmt = select(Alert).order_by(Alert.created_at.desc(), Alert.id.desc())
    if status is not None:
        stmt = stmt.where(Alert.status == status)
    if severity is not None:
        stmt = stmt.where(Alert.severity == severity)
    if source_ip is not None:
        stmt = stmt.where(Alert.source_ip == source_ip)
    stmt = stmt.limit(limit).offset(offset)
    return list(db.scalars(stmt))


def update_status(db: Session, alert: Alert, status: AlertStatus) -> Alert:
    alert.status = status
    db.commit()
    db.refresh(alert)
    return alert
