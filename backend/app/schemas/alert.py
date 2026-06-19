"""Schemas for reading and triaging alerts."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import AlertStatus, Severity


class AlertRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: int | None
    rule_id: int | None
    source_ip: str | None
    title: str
    description: str | None
    severity: Severity
    mitre_technique: str | None
    score: float
    status: AlertStatus
    created_at: datetime
    updated_at: datetime


class AlertStatusUpdate(BaseModel):
    """Triage action: move an alert through its lifecycle."""

    status: AlertStatus
