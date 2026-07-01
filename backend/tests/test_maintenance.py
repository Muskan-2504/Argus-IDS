"""Tests for the admin maintenance (clear data) endpoint."""

from collections.abc import Callable
from datetime import UTC, datetime

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.enums import Role, Severity
from app.models.event import Event
from app.models.user import User


def _seed(db: Session) -> None:
    db.add(Event(timestamp=datetime(2026, 6, 10, tzinfo=UTC), source_ip="203.0.113.5", raw={}))
    db.add(
        Alert(
            source_ip="203.0.113.5",
            title="Test alert",
            severity=Severity.high,
            score=80.0,
        )
    )
    db.commit()


def test_clear_removes_events_and_alerts(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    _seed(db_session)
    make_user("admin_user", role=Role.admin)

    resp = client.post("/api/maintenance/clear", headers=auth_headers("admin_user"))
    assert resp.status_code == 200, resp.text
    deleted = resp.json()["deleted"]
    assert deleted["events"] == 1
    assert deleted["alerts"] == 1

    assert db_session.query(Event).count() == 0
    assert db_session.query(Alert).count() == 0


def test_clear_requires_admin(
    client: TestClient,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    make_user("analyst_user", role=Role.analyst)
    resp = client.post("/api/maintenance/clear", headers=auth_headers("analyst_user"))
    assert resp.status_code == 403
