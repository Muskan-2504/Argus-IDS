"""Alert queries and triage updates."""

from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.enrichment import IpEnrichment
from app.models.enums import AlertStatus, Severity
from app.schemas.alert import AlertRead, EnrichmentRead


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


def enrichment_map(db: Session, ips: Iterable[str | None]) -> dict[str, IpEnrichment]:
    """Fetch enrichment rows for the given IPs in a single query (no N+1)."""
    wanted = {ip for ip in ips if ip}
    if not wanted:
        return {}
    rows = db.scalars(select(IpEnrichment).where(IpEnrichment.ip.in_(wanted)))
    return {row.ip: row for row in rows}


def to_read(alert: Alert, enrichment: dict[str, IpEnrichment]) -> AlertRead:
    """Build the API/stream DTO for an alert, attaching enrichment if present."""
    read = AlertRead.model_validate(alert)
    enr = enrichment.get(alert.source_ip) if alert.source_ip else None
    if enr is not None:
        read.enrichment = EnrichmentRead.model_validate(enr)
    return read
