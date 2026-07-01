"""Detection engine: evaluate rules against events and produce findings.

A :class:`Finding` is the engine's internal, storage-agnostic verdict; the
orchestration layer (added later in this module) turns findings into persisted
``Alert`` rows. Keeping evaluation pure makes every rule type unit-testable
without a database for the match path.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from urllib.parse import unquote

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.crud import alert as alert_crud
from app.detection.anomaly import detect_anomalies
from app.detection.definitions import MatchRule, ThresholdRule, get_field, selection_matches
from app.detection.finding import Finding
from app.detection.loader import load_enabled_rules
from app.detection.scoring import score_finding
from app.models.alert import Alert
from app.models.enums import AlertStatus
from app.models.event import Event
from app.models.rule import DetectionRule
from app.realtime.broadcaster import broadcaster


def evaluate_match_rule(rule: MatchRule, events: Iterable[Event]) -> list[Finding]:
    """Return a finding for each event whose field matches a rule pattern."""
    findings: list[Finding] = []
    for event in events:
        if not selection_matches(event, rule.selection):
            continue
        value = get_field(event, rule.field)
        if not isinstance(value, str):
            continue
        candidate = unquote(value) if rule.decode == "url" else value
        if any(pattern.search(candidate) for pattern in rule.compiled):
            findings.append(
                Finding(
                    rule_key=rule.key,
                    title=f"{rule.name} from {event.source_ip}",
                    description=f"Matched {rule.field}: {candidate[:200]}",
                    severity=rule.severity,
                    mitre_technique=rule.mitre_technique,
                    score=0.9,
                    source_ip=event.source_ip,
                    event_id=event.id,
                )
            )
    return findings


def evaluate_threshold_rule(
    rule: ThresholdRule, db: Session, group_values: Iterable[str | None]
) -> list[Finding]:
    """Return a finding per group whose windowed count exceeds the threshold.

    The window ends at the group's most recent event (so replayed historical
    logs are evaluated on their own timeline, not wall-clock). The selection
    filter is applied in Python to stay dialect-agnostic over the JSON ``raw``.
    """
    column = getattr(Event, rule.group_by)
    findings: list[Finding] = []

    for value in {v for v in group_values if v is not None}:
        window_end = db.scalar(select(func.max(Event.timestamp)).where(column == value))
        if window_end is None:
            continue
        window_start = window_end - timedelta(seconds=rule.window_seconds)
        events = db.scalars(
            select(Event).where(
                column == value,
                Event.timestamp >= window_start,
                Event.timestamp <= window_end,
            )
        ).all()

        matched = [e for e in events if selection_matches(e, rule.selection)]
        if rule.distinct_field is not None:
            observed = len({get_field(e, rule.distinct_field) for e in matched} - {None})
            unit = f"distinct {rule.distinct_field.split('.')[-1]}"
        else:
            observed = len(matched)
            unit = "events"

        if observed < rule.threshold:
            continue

        score = min(1.0, 0.5 + 0.5 * (observed - rule.threshold) / rule.threshold)
        findings.append(
            Finding(
                rule_key=rule.key,
                title=f"{rule.name} from {value}",
                description=(
                    f"{observed} {unit} in {rule.window_seconds}s (threshold {rule.threshold})"
                ),
                severity=rule.severity,
                mitre_technique=rule.mitre_technique,
                score=round(score, 2),
                source_ip=value if rule.group_by == "source_ip" else None,
            )
        )
    return findings


def _is_duplicate(db: Session, finding: Finding, rule_id: int | None) -> bool:
    """Suppress alert storms.

    A match finding is unique per (rule, triggering event). A threshold finding
    is suppressed while an *open* alert already exists for the same (rule,
    source IP) — re-detection won't spam until an analyst resolves it.
    """
    if finding.event_id is not None:
        existing = db.scalar(
            select(Alert.id).where(Alert.rule_id == rule_id, Alert.event_id == finding.event_id)
        )
    else:
        existing = db.scalar(
            select(Alert.id).where(
                Alert.rule_id == rule_id,
                Alert.source_ip == finding.source_ip,
                Alert.status == AlertStatus.open,
            )
        )
    return existing is not None


def _persist_findings(db: Session, findings: list[Finding]) -> list[Alert]:
    """Score, deduplicate, persist, and broadcast a batch of findings."""
    if not findings:
        return []

    rule_ids: dict[str, int] = {
        row.key: row.id for row in db.execute(select(DetectionRule.key, DetectionRule.id)).all()
    }
    enrichment = alert_crud.enrichment_map(db, [f.source_ip for f in findings])

    alerts: list[Alert] = []
    for finding in findings:
        rule_id = rule_ids.get(finding.rule_key)
        if _is_duplicate(db, finding, rule_id):
            continue
        enr = enrichment.get(finding.source_ip) if finding.source_ip else None
        severity, score = score_finding(finding, enr.abuse_score if enr else None)
        alert = Alert(
            event_id=finding.event_id,
            rule_id=rule_id,
            source_ip=finding.source_ip,
            title=finding.title,
            description=finding.description,
            severity=severity,
            mitre_technique=finding.mitre_technique,
            score=score,
            status=AlertStatus.open,
        )
        db.add(alert)
        alerts.append(alert)

    db.commit()
    for alert in alerts:
        db.refresh(alert)

    # Push new alerts to any connected dashboards (real-time feed).
    for alert in alerts:
        payload = alert_crud.to_read(alert, enrichment).model_dump(mode="json")
        broadcaster.publish({"type": "alert", "data": payload})

    return alerts


def run_detection(db: Session, events: list[Event]) -> list[Alert]:
    """Evaluate all enabled rules against a freshly-ingested batch of events
    and persist any new alerts they raise.
    """
    findings: list[Finding] = []
    for rule in load_enabled_rules():
        if isinstance(rule, MatchRule):
            findings.extend(evaluate_match_rule(rule, events))
        else:
            group_values = {getattr(e, rule.group_by, None) for e in events}
            findings.extend(evaluate_threshold_rule(rule, db, group_values))
    return _persist_findings(db, findings)


def run_anomaly_scan(db: Session, *, window_seconds: int = 300) -> list[Alert]:
    """Run the statistical + ML anomaly detectors over the most recent window
    of events and persist any new alerts.
    """
    window_end = db.scalar(select(func.max(Event.timestamp)))
    if window_end is None:
        return []
    window_start = window_end - timedelta(seconds=window_seconds)
    events = list(
        db.scalars(
            select(Event).where(Event.timestamp >= window_start, Event.timestamp <= window_end)
        )
    )
    return _persist_findings(db, detect_anomalies(events))
