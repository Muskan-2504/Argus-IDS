"""End-to-end tests for the ingestion endpoints (auth gating + persistence)."""

from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import Role
from app.models.event import Event
from app.models.user import User

AUTH_LINES = [
    "Oct 10 13:55:30 web01 sshd[2001]: Failed password for invalid user admin "
    "from 203.0.113.5 port 54321 ssh2",
    "Oct 10 13:55:40 web01 sshd[2010]: Accepted password for alice from 10.0.0.5 port 53210 ssh2",
    "Oct 10 13:56:05 web01 sudo: not an ssh line, should be skipped",
]


def _event_count(db: Session) -> int:
    return db.scalar(select(func.count()).select_from(Event)) or 0


def test_ingest_requires_authentication(client: TestClient) -> None:
    resp = client.post("/api/ingest", json={"source_type": "auth_log", "lines": ["x"]})
    assert resp.status_code == 401


def test_viewer_cannot_ingest(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("viewer_user", role=Role.viewer)
    resp = client.post(
        "/api/ingest",
        headers=auth_headers("viewer_user"),
        json={"source_type": "auth_log", "lines": ["x"]},
    )
    assert resp.status_code == 403


def test_analyst_ingests_auth_log(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    make_user("analyst_user", role=Role.analyst)
    resp = client.post(
        "/api/ingest",
        headers=auth_headers("analyst_user"),
        json={"source_type": "auth_log", "lines": AUTH_LINES, "source_name": "web01"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["received"] == 3
    assert body["parsed"] == 2  # the sudo line is skipped
    assert body["skipped"] == 1
    assert body["source_id"] is not None
    assert _event_count(db_session) == 2


def test_ingest_invalid_source_type_returns_422(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("analyst_user", role=Role.analyst)
    resp = client.post(
        "/api/ingest",
        headers=auth_headers("analyst_user"),
        json={"source_type": "not-a-real-format", "lines": ["anything"]},
    )
    assert resp.status_code == 422  # rejected by enum validation


def test_ingest_custom_source_type_uses_generic_parser(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("analyst_user", role=Role.analyst)
    resp = client.post(
        "/api/ingest",
        headers=auth_headers("analyst_user"),
        json={"source_type": "custom", "lines": ["request from 203.0.113.40 blocked"]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["parsed"] == 1  # generic parser handles arbitrary text


def test_ingest_file_upload(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    make_user("analyst_user", role=Role.analyst)
    content = "\n".join(AUTH_LINES)
    resp = client.post(
        "/api/ingest/file",
        headers=auth_headers("analyst_user"),
        data={"source_type": "auth_log"},
        files={"file": ("auth.log", content, "text/plain")},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["parsed"] == 2
    assert _event_count(db_session) == 2
