"""An alert raised when a rule or anomaly detector fires on an event."""

from datetime import datetime

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.models.enums import AlertStatus, Severity


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("events.id", ondelete="SET NULL"), nullable=True
    )
    rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_rules.id", ondelete="SET NULL"), nullable=True
    )
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        Enum(Severity), default=Severity.medium, nullable=False, index=True
    )
    mitre_technique: Mapped[str | None] = mapped_column(String(20), nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus), default=AlertStatus.open, nullable=False, index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
