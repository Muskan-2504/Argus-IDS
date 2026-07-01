"""End-to-end tests for the anomaly-scan endpoint."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.detection.sync import sync_rules
from app.models.enums import Role
from app.models.event import Event
from app.models.user import User

BASE = datetime(2024, 10, 10, 13, 0, 0, tzinfo=UTC)


def _seed_population(db: Session) -> None:
    events: list[Event] = []
    for n in range(10):  # ten quiet, similar IPs
        events += [
            Event(
                timestamp=BASE + timedelta(seconds=i),
                source_ip=f"10.0.0.{n}",
                protocol="http",
                raw={"path": "/", "status": 200},
            )
            for i in range(4)
        ]
    # one loud port-scanning outlier
    events += [
        Event(
            timestamp=BASE + timedelta(seconds=i),
            source_ip="203.0.113.99",
            protocol="tcp",
            raw={"dest_port": 1000 + i},
        )
        for i in range(40)
    ]
    db.add_all(events)
    db.commit()


def test_anomaly_scan_flags_outlier(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    _seed_population(db_session)
    make_user("analyst_user", role=Role.analyst)

    resp = client.post(
        "/api/detection/anomaly-scan?window_seconds=600",
        headers=auth_headers("analyst_user"),
    )
    assert resp.status_code == 200, resp.text
    assert "203.0.113.99" in {a["source_ip"] for a in resp.json()}


def test_anomaly_scan_requires_analyst(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("viewer_user", role=Role.viewer)
    resp = client.post("/api/detection/anomaly-scan", headers=auth_headers("viewer_user"))
    assert resp.status_code == 403
