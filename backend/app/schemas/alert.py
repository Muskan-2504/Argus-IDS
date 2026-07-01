"""Schemas for reading and triaging alerts."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.enums import AlertStatus, Severity


class EnrichmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    country: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    abuse_score: int | None = None


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
    enrichment: EnrichmentRead | None = None


class AlertStatusUpdate(BaseModel):
    """Triage action: move an alert through its lifecycle."""

    status: AlertStatus
