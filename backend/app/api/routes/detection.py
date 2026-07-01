"""On-demand detection operations (analyst+)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import require_min_role
from app.crud import alert as alert_crud
from app.db.session import get_db
from app.detection.engine import run_anomaly_scan
from app.detection.mitre import lookup as lookup_technique
from app.models.alert import Alert
from app.models.enums import Role
from app.models.rule import DetectionRule
from app.schemas.alert import AlertRead
from app.schemas.detection import MitreCoverage

router = APIRouter(
    prefix="/detection",
    tags=["detection"],
    dependencies=[Depends(require_min_role(Role.analyst))],
)

DbSession = Annotated[Session, Depends(get_db)]


@router.post("/anomaly-scan", response_model=list[AlertRead])
def anomaly_scan(
    db: DbSession,
    window_seconds: Annotated[int, Query(ge=10, le=86_400)] = 300,
) -> list[AlertRead]:
    """Run the statistical + ML anomaly detectors over the recent event window
    and return any new alerts they raise."""
    alerts = run_anomaly_scan(db, window_seconds=window_seconds)
    enrichment = alert_crud.enrichment_map(db, [a.source_ip for a in alerts])
    return [alert_crud.to_read(a, enrichment) for a in alerts]


@router.get("/mitre-coverage", response_model=list[MitreCoverage])
def mitre_coverage(db: DbSession) -> list[MitreCoverage]:
    """Report which MITRE ATT&CK techniques the enabled rules cover, with how
    many rules map to each and how many alerts each has raised."""
    rule_counts: dict[str, int] = {
        tech: count
        for tech, count in db.execute(
            select(DetectionRule.mitre_technique, func.count())
            .where(DetectionRule.mitre_technique.is_not(None), DetectionRule.enabled.is_(True))
            .group_by(DetectionRule.mitre_technique)
        ).all()
        if tech is not None
    }
    alert_counts: dict[str, int] = {
        tech: count
        for tech, count in db.execute(
            select(Alert.mitre_technique, func.count())
            .where(Alert.mitre_technique.is_not(None))
            .group_by(Alert.mitre_technique)
        ).all()
        if tech is not None
    }

    coverage: list[MitreCoverage] = []
    for tech, count in rule_counts.items():
        info = lookup_technique(tech)
        coverage.append(
            MitreCoverage(
                technique=tech,
                name=info.name if info else None,
                tactic=info.tactic if info else None,
                rule_count=count,
                alert_count=alert_counts.get(tech, 0),
            )
        )
    coverage.sort(key=lambda c: (c.tactic or "~", c.technique))
    return coverage
