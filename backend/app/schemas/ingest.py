"""Schemas for the log-ingestion endpoints."""

from pydantic import BaseModel, Field

from app.models.enums import SourceType


class IngestRequest(BaseModel):
    """A batch of raw log lines to parse and store."""

    source_type: SourceType
    lines: list[str] = Field(min_length=1, description="Raw log lines to parse.")
    source_name: str | None = Field(
        default=None, max_length=100, description="Optional named source to group events under."
    )


class IngestResult(BaseModel):
    """Outcome of an ingest call."""

    source_type: SourceType
    source_id: int | None = None
    received: int  # non-blank lines submitted
    parsed: int  # lines successfully turned into events
    skipped: int  # lines the parser did not recognize
    alerts: int = 0  # alerts raised by detection on this batch
