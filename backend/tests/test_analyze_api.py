"""End-to-end tests for the interactive /ingest/analyze endpoint."""

from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.detection.sync import sync_rules
from app.models.enums import Role
from app.models.user import User

# Six failed SSH logins from one IP within ~10s -> trips brute_force_ssh (>=5/60s).
BRUTE_FORCE = "\n".join(
    f"Jun 10 06:11:{1 + 2 * i:02d} web-01 sshd[2010{i}]: "
    f"Failed password for invalid user admin from 198.51.100.42 port 5400{i} ssh2"
    for i in range(6)
)


def test_analyze_auto_detects_and_finds_threat(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)

    resp = client.post(
        "/api/ingest/analyze",
        json={"text": BRUTE_FORCE},  # no source_type -> auto-detect
        headers=auth_headers("analyst_user"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["detected_source_type"] == "auth_log"
    assert body["auto_detected"] is True
    assert body["parsed"] == 6
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["mitre_technique"] == "T1110"
    assert body["alerts"][0]["source_ip"] == "198.51.100.42"


def test_analyze_falls_back_to_generic_for_unknown_format(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)
    resp = client.post(
        "/api/ingest/analyze",
        json={"text": "this is not a standard log line"},
        headers=auth_headers("analyst_user"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["detected_source_type"] == "custom"  # generic fallback
    assert body["auto_detected"] is True
    assert body["parsed"] == 1  # nothing is dropped
    assert body["alerts"] == []  # but nothing malicious found


def test_analyze_generic_detects_brute_force_in_custom_format(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)
    # A non-standard SSH log (no sshd[pid]: syslog shape) — only the generic
    # parser can read it. Six failures in <60s from one IP -> brute_force_ssh.
    text = "\n".join(
        f"2026-06-10T06:11:{1 + 2 * i:02d}Z host sshd: authentication failure "
        f"for root from 198.51.100.77 port 5000{i}"
        for i in range(6)
    )
    resp = client.post(
        "/api/ingest/analyze",
        json={"text": text, "source_type": "custom"},
        headers=auth_headers("analyst_user"),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body["alerts"]) == 1
    assert body["alerts"][0]["mitre_technique"] == "T1110"
    assert body["alerts"][0]["source_ip"] == "198.51.100.77"


def test_analyze_honors_explicit_source_type(
    client: TestClient,
    db_session: Session,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    sync_rules(db_session)
    make_user("analyst_user", role=Role.analyst)
    resp = client.post(
        "/api/ingest/analyze",
        json={"text": BRUTE_FORCE, "source_type": "auth_log"},
        headers=auth_headers("analyst_user"),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["auto_detected"] is False


def test_analyze_requires_analyst(
    client: TestClient,
    make_user: Callable[..., User],
    auth_headers: Callable[..., dict[str, str]],
) -> None:
    make_user("viewer_user", role=Role.viewer)
    resp = client.post(
        "/api/ingest/analyze",
        json={"text": BRUTE_FORCE},
        headers=auth_headers("viewer_user"),
    )
    assert resp.status_code == 403
