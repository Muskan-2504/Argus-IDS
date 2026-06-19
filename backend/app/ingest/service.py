"""Ingestion orchestration: parse raw log lines into persisted events.

This is the wire the original project never connected — raw logs in, parsed
and indexed ``Event`` rows out, ready for the detection engine in M2.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.engine import run_detection
from app.ingest.parsers import get_parser
from app.models.enums import SourceType
from app.models.event import Event
from app.models.log_source import LogSource
from app.schemas.ingest import IngestResult


def _get_or_create_source(db: Session, name: str, source_type: SourceType) -> LogSource:
    source = db.scalar(select(LogSource).where(LogSource.name == name))
    if source is None:
        source = LogSource(name=name, type=source_type)
        db.add(source)
        db.commit()
        db.refresh(source)
    return source


def ingest_lines(
    db: Session,
    *,
    source_type: SourceType,
    lines: list[str],
    source_name: str | None = None,
) -> IngestResult:
    """Parse ``lines`` with the parser for ``source_type`` and store the events.

    Raises :class:`ValueError` if no parser exists for ``source_type``.
    """
    parser = get_parser(source_type)  # may raise ValueError -> 422 at the route
    source = _get_or_create_source(db, source_name, source_type) if source_name else None
    source_id = source.id if source else None

    non_blank = [line for line in lines if line.strip()]
    events = [
        Event(
            source_id=source_id,
            timestamp=parsed.timestamp,
            source_ip=parsed.source_ip,
            dest_ip=parsed.dest_ip,
            protocol=parsed.protocol,
            raw=parsed.raw,
        )
        for parsed in parser.parse("\n".join(non_blank))
    ]
    db.add_all(events)
    db.commit()

    # Run detection synchronously over the new batch (made async in M4).
    alerts = run_detection(db, events) if events else []

    return IngestResult(
        source_type=source_type,
        source_id=source_id,
        received=len(non_blank),
        parsed=len(events),
        skipped=len(non_blank) - len(events),
        alerts=len(alerts),
    )
