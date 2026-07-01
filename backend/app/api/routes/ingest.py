"""Log-ingestion endpoints. All require the analyst role or higher."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import require_min_role
from app.crud import alert as alert_crud
from app.db.session import get_db
from app.ingest.detect import sniff_source_type
from app.ingest.service import analyze_lines, ingest_lines
from app.models.enums import Role, SourceType
from app.schemas.ingest import AnalyzeRequest, AnalyzeResult, IngestRequest, IngestResult

router = APIRouter(
    prefix="/ingest",
    tags=["ingest"],
    dependencies=[Depends(require_min_role(Role.analyst))],
)

DbSession = Annotated[Session, Depends(get_db)]


@router.post("", response_model=IngestResult)
def ingest(payload: IngestRequest, db: DbSession) -> IngestResult:
    """Ingest a JSON batch of raw log lines."""
    try:
        return ingest_lines(
            db,
            source_type=payload.source_type,
            lines=payload.lines,
            source_name=payload.source_name,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


@router.post("/analyze", response_model=AnalyzeResult)
def analyze(payload: AnalyzeRequest, db: DbSession) -> AnalyzeResult:
    """Analyze pasted log text and return the threats found in it.

    When ``source_type`` is omitted the format is auto-detected from the
    content; unrecognized input yields a 422 asking the user to pick a format.
    Unlike :func:`ingest`, this returns the actual alert rows raised so the UI
    can show what was detected, not just a count.
    """
    source_type = payload.source_type
    auto_detected = source_type is None
    if source_type is None:
        # Sniff a known format; otherwise fall back to the format-agnostic parser
        # so arbitrary logs still get their key fields extracted.
        source_type = sniff_source_type(payload.text) or SourceType.custom

    try:
        result, alerts = analyze_lines(
            db,
            source_type=source_type,
            lines=payload.text.splitlines(),
            source_name=payload.source_name,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc

    enrichment = alert_crud.enrichment_map(db, [a.source_ip for a in alerts])
    return AnalyzeResult(
        detected_source_type=source_type,
        auto_detected=auto_detected,
        received=result.received,
        parsed=result.parsed,
        skipped=result.skipped,
        alerts=[alert_crud.to_read(a, enrichment) for a in alerts],
    )


@router.post("/file", response_model=IngestResult)
async def ingest_file(
    db: DbSession,
    source_type: Annotated[SourceType, Form()],
    file: Annotated[UploadFile, File()],
    source_name: Annotated[str | None, Form()] = None,
) -> IngestResult:
    """Ingest an uploaded log file (UTF-8, one log line per line)."""
    content = (await file.read()).decode("utf-8", errors="replace")
    try:
        return ingest_lines(
            db,
            source_type=source_type,
            lines=content.splitlines(),
            source_name=source_name or file.filename,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
