"""Schemas for the log-ingestion endpoints."""

from pydantic import BaseModel, Field

from app.models.enums import SourceType
from app.schemas.alert import AlertRead


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


class AnalyzeRequest(BaseModel):
    """An interactive request to analyze pasted log text for threats."""

    text: str = Field(min_length=1, description="Raw log text — one log line per line.")
    source_type: SourceType | None = Field(
        default=None,
        description="Log format. Omit or send null to auto-detect from the content.",
    )
    source_name: str | None = Field(
        default=None, max_length=100, description="Optional named source to group events under."
    )


class AnalyzeResult(BaseModel):
    """Outcome of an analyze call: parse stats plus the alerts this batch raised."""

    detected_source_type: SourceType
    auto_detected: bool  # True when the format was sniffed rather than supplied
    received: int  # non-blank lines submitted
    parsed: int  # lines successfully turned into events
    skipped: int  # lines the parser did not recognize
    alerts: list[AlertRead]  # threats found in this batch
