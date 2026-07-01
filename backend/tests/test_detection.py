"""Unit tests for the detection engine (rules, evaluators, orchestration)."""

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.detection.engine import (
    evaluate_match_rule,
    evaluate_threshold_rule,
    run_detection,
)
from app.detection.loader import load_rules
from app.detection.sync import sync_rules
from app.models.event import Event

RULES = {r.key: r for r in load_rules()}
BASE = datetime(2024, 10, 10, 13, 55, 0, tzinfo=UTC)


def _add_events(db: Session, **kwargs: object) -> list[Event]:
    count = int(kwargs.pop("count"))  # type: ignore[arg-type]
    events = []
    for i in range(count):
        event = Event(timestamp=BASE + timedelta(seconds=i), **kwargs)  # type: ignore[arg-type]
        db.add(event)
        events.append(event)
    db.commit()
    for event in events:
        db.refresh(event)
    return events


def test_brute_force_fires_at_threshold(db_session: Session) -> None:
    _add_events(
        db_session, count=6, source_ip="203.0.113.5", protocol="ssh", raw={"outcome": "failed"}
    )
    findings = evaluate_threshold_rule(RULES["brute_force_ssh"], db_session, ["203.0.113.5"])
    assert len(findings) == 1
    assert findings[0].severity.value == "high"
    assert findings[0].mitre_technique == "T1110"


def test_brute_force_silent_below_threshold(db_session: Session) -> None:
    _add_events(
        db_session, count=4, source_ip="203.0.113.5", protocol="ssh", raw={"outcome": "failed"}
    )
    assert evaluate_threshold_rule(RULES["brute_force_ssh"], db_session, ["203.0.113.5"]) == []


def test_successful_logins_are_not_brute_force(db_session: Session) -> None:
    _add_events(
        db_session, count=6, source_ip="10.0.0.5", protocol="ssh", raw={"outcome": "accepted"}
    )
    assert evaluate_threshold_rule(RULES["brute_force_ssh"], db_session, ["10.0.0.5"]) == []


def test_port_scan_counts_distinct_ports(db_session: Session) -> None:
    events = []
    for port in range(12):
        events.append(
            Event(
                timestamp=BASE + timedelta(seconds=port),
                source_ip="203.0.113.66",
                protocol="tcp",
                raw={"dest_port": 1000 + port},
            )
        )
    db_session.add_all(events)
    db_session.commit()
    findings = evaluate_threshold_rule(RULES["port_scan"], db_session, ["203.0.113.66"])
    assert len(findings) == 1
    assert "distinct dest_port" in findings[0].description


def test_sqli_match_detects_union_select() -> None:
    class FakeEvent:
        id = 1
        source_ip = "203.0.113.22"
        protocol = "http"
        raw = {"path": "/p?id=1%20UNION%20SELECT%20pw%20FROM%20users"}

    findings = evaluate_match_rule(RULES["sqli_probe"], [FakeEvent()])
    assert len(findings) == 1
    assert findings[0].mitre_technique == "T1190"


def test_run_detection_links_rule_and_dedupes(db_session: Session) -> None:
    sync_rules(db_session)
    events = _add_events(
        db_session, count=6, source_ip="203.0.113.5", protocol="ssh", raw={"outcome": "failed"}
    )
    first = run_detection(db_session, events)
    assert len(first) == 1
    assert first[0].rule_id is not None  # linked to the synced DB rule
    # Re-running over the same events raises nothing (open alert already exists).
    assert run_detection(db_session, events) == []


def test_sync_rules_is_idempotent(db_session: Session) -> None:
    # 4 YAML rules + 2 built-in anomaly detectors.
    assert sync_rules(db_session) == (6, 0)
    assert sync_rules(db_session) == (0, 6)
