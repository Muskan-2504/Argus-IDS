"""Tests for the MITRE catalog, AlertRead resolution, and coverage endpoint."""

from collections.abc import Callable
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.detection.mitre import lookup
from app.detection.sync import sync_rules
from app.models.alert import Alert
from app.models.enums import AlertStatus, Role, Severity
from app.models.user import User
from app.schemas.alert import AlertRead


def _alert_read(mitre_technique: str | None) -> AlertRead:
    return AlertRead(
        id=1,
        event_id=None,
        rule_id=None,
        source_ip="203.0.113.5",
        title="Test",
        description=None,
        severity=Severity.high,
        mitre_technique=mitre_technique,
        score=80.0,
        status=AlertStatus.open,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )


def test_lookup_known_technique() -> None:
    info = lookup("T1110")
    assert info is not None
    assert info.name == "Brute Force"
    assert info.tactic == "Credential Access"


def test_lookup_subtechnique_falls_back_to_parent() -> None:
    info = lookup("T1110.999")  # unknown sub-technique
    assert info is not None
    assert info.name == "Brute Force"


def test_lookup_unknown_and_none() -> None:
    assert lookup("T9999") is None
    assert lookup(None) is None


def test_alertread_resolves_technique_name_and_tactic() -> None:
    read = _alert_read("T1190")
    assert read.technique_name == "Exploit Public-Facing Application"
    assert read.tactic == "Initial Access"


def test_alertread_no_technique_leaves_fields_none() -> None:
    read = _alert_read(None)
    assert read.technique_name is None
    assert read.tactic is None


def test_mitre_coverage_endpoint(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)  # loads the YAML + anomaly rules
    db_session.add(
        Alert(
            source_ip="203.0.113.5",
            title="bf",
            severity=Severity.high,
            mitre_technique="T1110",
            score=80.0,
        )
    )
    db_session.commit()
    make_user("analyst_user", role=Role.analyst)

    resp = client.get("/api/detection/mitre-coverage", headers=auth_headers("analyst_user"))
    assert resp.status_code == 200, resp.text
    by_tech = {row["technique"]: row for row in resp.json()}
    assert by_tech["T1110"]["name"] == "Brute Force"
    assert by_tech["T1110"]["tactic"] == "Credential Access"
    assert by_tech["T1110"]["rule_count"] >= 1
    assert by_tech["T1110"]["alert_count"] == 1


def test_mitre_coverage_requires_analyst(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("viewer_user", role=Role.viewer)
    resp = client.get("/api/detection/mitre-coverage", headers=auth_headers("viewer_user"))
    assert resp.status_code == 403
