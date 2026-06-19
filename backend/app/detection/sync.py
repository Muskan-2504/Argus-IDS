"""Synchronize the YAML rule files into the ``detection_rules`` table.

Keeping a DB row per rule lets alerts reference their rule by id and makes the
active ruleset visible/auditable through the API. The full rule body is stored
in the ``definition`` JSON column.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.detection.loader import load_rules
from app.models.rule import DetectionRule


def sync_rules(db: Session) -> tuple[int, int]:
    """Upsert every YAML rule. Returns ``(created, updated)`` counts."""
    created = updated = 0
    for rule in load_rules():
        definition = rule.model_dump(mode="json")
        existing = db.scalar(select(DetectionRule).where(DetectionRule.key == rule.key))
        if existing is None:
            db.add(
                DetectionRule(
                    key=rule.key,
                    name=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                    mitre_technique=rule.mitre_technique,
                    enabled=rule.enabled,
                    definition=definition,
                )
            )
            created += 1
        else:
            existing.name = rule.name
            existing.description = rule.description
            existing.severity = rule.severity
            existing.mitre_technique = rule.mitre_technique
            existing.enabled = rule.enabled
            existing.definition = definition
            updated += 1
    db.commit()
    return created, updated
