"""Log-ingestion endpoints. All require the analyst role or higher."""

from typing import Annotated

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from app.api.deps import require_min_role
from app.db.session import get_db
from app.ingest.service import ingest_lines
from app.models.enums import Role, SourceType
from app.schemas.ingest import IngestRequest, IngestResult

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
