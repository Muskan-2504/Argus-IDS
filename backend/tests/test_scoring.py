"""Tests for risk scoring + severity escalation."""

from app.detection.finding import Finding
from app.detection.scoring import score_finding
from app.models.enums import Severity


def _finding(severity: Severity, score: float) -> Finding:
    return Finding(
        rule_key="x",
        title="t",
        description="d",
        severity=severity,
        mitre_technique=None,
        score=score,
    )


def test_score_without_reputation() -> None:
    severity, risk = score_finding(_finding(Severity.medium, 0.5))
    assert severity is Severity.medium
    assert risk == 55.0  # base 50 + 0.5*10


def test_reputation_raises_score_and_escalates_severity() -> None:
    severity, risk = score_finding(_finding(Severity.high, 1.0), abuse_score=90)
    assert severity is Severity.critical  # escalated from high
    assert risk == 100.0  # 70 + 10 + 27 -> capped at 100


def test_low_reputation_does_not_escalate() -> None:
    severity, risk = score_finding(_finding(Severity.medium, 0.0), abuse_score=20)
    assert severity is Severity.medium
    assert risk == 56.0  # 50 + 0 + 20*0.3


def test_critical_severity_does_not_overflow_ladder() -> None:
    severity, _ = score_finding(_finding(Severity.critical, 1.0), abuse_score=100)
    assert severity is Severity.critical
