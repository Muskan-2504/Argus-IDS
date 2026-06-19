"""End-to-end tests: ingest -> detection -> alerts API + triage RBAC."""

from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.detection.sync import sync_rules
from app.models.enums import Role
from app.models.user import User


def _failed_ssh_lines(ip: str, n: int) -> list[str]:
    return [
        f"Oct 10 13:55:{30 + i:02d} web01 sshd[200{i}]: "
        f"Failed password for root from {ip} port 5432{i} ssh2"
        for i in range(n)
    ]


def test_ingest_brute_force_raises_alert(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)
    resp = client.post(
        "/api/ingest",
        headers=auth_headers("analyst_user"),
        json={"source_type": "auth_log", "lines": _failed_ssh_lines("203.0.113.5", 6)},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["alerts"] == 1

    listing = client.get("/api/alerts", headers=auth_headers("analyst_user"))
    assert listing.status_code == 200
    assert any(a["mitre_technique"] == "T1110" for a in listing.json())


def test_ingest_sqli_raises_alert(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)
    line = (
        "203.0.113.22 - - [10/Oct/2024:13:51:11 +0000] "
        '"GET /p?id=1%20UNION%20SELECT%20pw%20FROM%20users HTTP/1.1" 500 0 "-" "sqlmap"'
    )
    resp = client.post(
        "/api/ingest",
        headers=auth_headers("analyst_user"),
        json={"source_type": "nginx", "lines": [line]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["alerts"] == 1


def test_alerts_require_authentication(client: TestClient) -> None:
    assert client.get("/api/alerts").status_code == 401


def test_viewer_can_read_but_not_triage(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)
    client.post(
        "/api/ingest",
        headers=auth_headers("analyst_user"),
        json={"source_type": "auth_log", "lines": _failed_ssh_lines("203.0.113.5", 6)},
    )
    make_user("viewer_user", role=Role.viewer)

    alert_id = client.get("/api/alerts", headers=auth_headers("viewer_user")).json()[0]["id"]
    forbidden = client.patch(
        f"/api/alerts/{alert_id}/status",
        headers=auth_headers("viewer_user"),
        json={"status": "resolved"},
    )
    assert forbidden.status_code == 403

    ok = client.patch(
        f"/api/alerts/{alert_id}/status",
        headers=auth_headers("analyst_user"),
        json={"status": "resolved"},
    )
    assert ok.status_code == 200
    assert ok.json()["status"] == "resolved"


def test_alerts_filter_by_severity(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)
    client.post(
        "/api/ingest",
        headers=auth_headers("analyst_user"),
        json={"source_type": "auth_log", "lines": _failed_ssh_lines("203.0.113.5", 6)},
    )
    headers = auth_headers("analyst_user")
    high = client.get("/api/alerts?severity=high", headers=headers)
    assert high.status_code == 200
    assert high.json() and all(a["severity"] == "high" for a in high.json())
    assert client.get("/api/alerts?severity=low", headers=headers).json() == []


def test_get_missing_alert_404(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("viewer_user", role=Role.viewer)
    assert client.get("/api/alerts/9999", headers=auth_headers("viewer_user")).status_code == 404
