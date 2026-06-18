"""A single normalized log event. The raw payload is kept in JSONB so no
information is lost, while the extracted fields are indexed for fast queries
(the "structured log indexing" the original report aspired to)."""

from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base
from app.db.types import JSONType


class Event(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    source_id: Mapped[int | None] = mapped_column(
        ForeignKey("log_sources.id", ondelete="SET NULL"), nullable=True
    )
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    dest_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(10), nullable=True)
    raw: Mapped[dict] = mapped_column(JSONType, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    __table_args__ = (Index("ix_events_source_ip_timestamp", "source_ip", "timestamp"),)
