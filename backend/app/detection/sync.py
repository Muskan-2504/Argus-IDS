"""Synchronize the YAML rule files into the ``detection_rules`` table.

Keeping a DB row per rule lets alerts reference their rule by id and makes the
active ruleset visible/auditable through the API. The full rule body is stored
in the ``definition`` JSON column.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.anomaly import ANOMALY_RULES
from app.detection.loader import load_rules
from app.models.enums import Severity
from app.models.rule import DetectionRule


def _upsert(
    db: Session,
    *,
    key: str,
    name: str,
    description: str | None,
    severity: Severity,
    mitre_technique: str | None,
    enabled: bool,
    definition: dict[str, Any],
) -> bool:
    """Insert or update a rule by key. Returns True if newly created."""
    existing = db.scalar(select(DetectionRule).where(DetectionRule.key == key))
    if existing is None:
        db.add(
            DetectionRule(
                key=key,
                name=name,
                description=description,
                severity=severity,
                mitre_technique=mitre_technique,
                enabled=enabled,
                definition=definition,
            )
        )
        return True
    existing.name = name
    existing.description = description
    existing.severity = severity
    existing.mitre_technique = mitre_technique
    existing.enabled = enabled
    existing.definition = definition
    return False


def sync_rules(db: Session) -> tuple[int, int]:
    """Upsert every YAML rule plus the built-in anomaly detectors. Returns
    ``(created, updated)`` counts."""
    created = updated = 0

    for rule in load_rules():
        is_new = _upsert(
            db,
            key=rule.key,
            name=rule.name,
            description=rule.description,
            severity=rule.severity,
            mitre_technique=rule.mitre_technique,
            enabled=rule.enabled,
            definition=rule.model_dump(mode="json"),
        )
        created, updated = (created + 1, updated) if is_new else (created, updated + 1)

    for anomaly in ANOMALY_RULES:
        is_new = _upsert(
            db,
            key=anomaly["key"],
            name=anomaly["name"],
            description=anomaly["description"],
            severity=anomaly["severity"],
            mitre_technique=anomaly["mitre_technique"],
            enabled=True,
            definition={"type": "anomaly"},
        )
        created, updated = (created + 1, updated) if is_new else (created, updated + 1)

    db.commit()
    return created, updated
