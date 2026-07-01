"""Risk scoring.

Turns a :class:`Finding` plus optional IP reputation into a final 0–100 risk
score and an (optionally escalated) severity. A detection from a known-abusive
IP is more urgent than the same detection from an unknown one — so reputation
both raises the score and can bump the severity.
"""

from __future__ import annotations

from app.detection.finding import Finding
from app.models.enums import Severity

_SEVERITY_BASE: dict[Severity, float] = {
    Severity.info: 10,
    Severity.low: 30,
    Severity.medium: 50,
    Severity.high: 70,
    Severity.critical: 90,
}

_SEVERITY_LADDER = [
    Severity.info,
    Severity.low,
    Severity.medium,
    Severity.high,
    Severity.critical,
]


def _escalate(severity: Severity, steps: int) -> Severity:
    index = min(len(_SEVERITY_LADDER) - 1, _SEVERITY_LADDER.index(severity) + steps)
    return _SEVERITY_LADDER[index]


def score_finding(finding: Finding, abuse_score: int | None = None) -> tuple[Severity, float]:
    """Return the (possibly escalated) severity and a 0–100 risk score."""
    risk = _SEVERITY_BASE[finding.severity]
    risk += finding.score * 10  # detector confidence: up to +10

    severity = finding.severity
    if abuse_score is not None:
        risk += abuse_score * 0.3  # reputation: up to +30
        if abuse_score >= 80:
            severity = _escalate(severity, 1)

    risk = max(0.0, min(100.0, risk))
    return severity, round(risk, 1)
