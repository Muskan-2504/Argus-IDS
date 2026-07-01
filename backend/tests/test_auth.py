"""End-to-end tests for registration, login, and RBAC enforcement."""

from collections.abc import Callable

from fastapi.testclient import TestClient

from app.models.enums import Role
from app.models.user import User


def test_register_creates_viewer(client: TestClient) -> None:
    resp = client.post(
        "/api/auth/register",
        json={"username": "newbie", "email": "newbie@example.com", "password": "password123"},
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["role"] == "viewer"
    assert "hashed_password" not in body  # never leak the hash


def test_register_rejects_short_password(client: TestClient) -> None:
    resp = client.post(
        "/api/auth/register",
        json={"username": "shorty", "email": "s@example.com", "password": "short"},
    )
    assert resp.status_code == 422


def test_register_duplicate_username_conflicts(
    client: TestClient, make_user: Callable[..., User]
) -> None:
    make_user("dupe")
    resp = client.post(
        "/api/auth/register",
        json={"username": "dupe", "email": "other@example.com", "password": "password123"},
    )
    assert resp.status_code == 409


def test_login_then_me(client: TestClient, make_user: Callable[..., User]) -> None:
    make_user("alice", role=Role.analyst)
    login = client.post("/api/auth/login", data={"username": "alice", "password": "password123"})
    assert login.status_code == 200, login.text
    token = login.json()["access_token"]

    me = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json()["username"] == "alice"
    assert me.json()["role"] == "analyst"


def test_login_wrong_password_rejected(client: TestClient, make_user: Callable[..., User]) -> None:
    make_user("bob")
    resp = client.post("/api/auth/login", data={"username": "bob", "password": "wrong-password"})
    assert resp.status_code == 401


def test_me_requires_authentication(client: TestClient) -> None:
    assert client.get("/api/auth/me").status_code == 401


def test_me_reads_back_reserved_domain_email(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    # Regression: reserved-domain emails (.local/.test/etc.) must read back
    # without the output schema re-validating and 500-ing.
    make_user("svc", email="svc@argus.local", role=Role.viewer)
    resp = client.get("/api/auth/me", headers=auth_headers("svc"))
    assert resp.status_code == 200
    assert resp.json()["email"] == "svc@argus.local"


def test_viewer_cannot_list_users(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("viewer_user", role=Role.viewer)
    resp = client.get("/api/users", headers=auth_headers("viewer_user"))
    assert resp.status_code == 403


def test_analyst_cannot_manage_users(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("analyst_user", role=Role.analyst)
    resp = client.get("/api/users", headers=auth_headers("analyst_user"))
    assert resp.status_code == 403


def test_admin_can_list_and_create_users(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("root", role=Role.admin)
    headers = auth_headers("root")

    listing = client.get("/api/users", headers=headers)
    assert listing.status_code == 200
    assert len(listing.json()) == 1

    created = client.post(
        "/api/users",
        headers=headers,
        json={
            "username": "analyst1",
            "email": "analyst1@example.com",
            "password": "password123",
            "role": "analyst",
        },
    )
    assert created.status_code == 201
    assert created.json()["role"] == "analyst"


def test_admin_cannot_change_own_role(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    admin = make_user("root", role=Role.admin)
    resp = client.patch(
        f"/api/users/{admin.id}/role",
        headers=auth_headers("root"),
        json={"role": "viewer"},
    )
    assert resp.status_code == 400


def test_admin_can_change_other_role(
    client: TestClient, make_user: Callable[..., User], auth_headers: Callable[..., dict[str, str]]
) -> None:
    make_user("root", role=Role.admin)
    target = make_user("victim", role=Role.viewer)
    resp = client.patch(
        f"/api/users/{target.id}/role",
        headers=auth_headers("root"),
        json={"role": "analyst"},
    )
    assert resp.status_code == 200
    assert resp.json()["role"] == "analyst"
