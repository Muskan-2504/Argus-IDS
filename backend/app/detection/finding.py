"""The engine's internal, storage-agnostic detection result."""

from __future__ import annotations

from dataclasses import dataclass

from app.models.enums import Severity


@dataclass
class Finding:
    """A single detection result, not yet persisted as an alert."""

    rule_key: str
    title: str
    description: str
    severity: Severity
    mitre_technique: str | None
    score: float
    source_ip: str | None = None
    event_id: int | None = None
