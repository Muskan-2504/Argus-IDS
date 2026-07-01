"""Schemas for detection-intelligence endpoints."""

from pydantic import BaseModel


class MitreCoverage(BaseModel):
    """How a single MITRE ATT&CK technique is covered by the deployed rules."""

    technique: str
    name: str | None = None
    tactic: str | None = None
    rule_count: int  # enabled rules mapped to this technique
    alert_count: int  # alerts raised for this technique so far
