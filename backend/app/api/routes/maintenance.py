"""Admin maintenance operations — reset demo/analyzed data."""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.api.deps import require_min_role
from app.db.session import get_db
from app.models.alert import Alert
from app.models.enrichment import IpEnrichment
from app.models.enums import Role
from app.models.event import Event
from app.models.log_source import LogSource

router = APIRouter(
    prefix="/maintenance",
    tags=["maintenance"],
    dependencies=[Depends(require_min_role(Role.admin))],
)

DbSession = Annotated[Session, Depends(get_db)]

# Tables wiped by a clear. Users and detection rules are intentionally kept.
_CLEARABLE = (Alert, Event, IpEnrichment, LogSource)


@router.post("/clear")
def clear_data(db: DbSession) -> dict[str, dict[str, int]]:
    """Delete all ingested events, alerts, and enrichment (admin only).

    Leaves user accounts and detection rules intact, so the system is ready to
    analyze fresh logs. Returns the row counts removed per table.
    """
    deleted: dict[str, int] = {}
    for model in _CLEARABLE:
        count = db.scalar(select(func.count()).select_from(model)) or 0
        db.execute(delete(model))
        deleted[model.__tablename__] = count
    db.commit()
    return {"deleted": deleted}
