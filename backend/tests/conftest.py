"""Shared pytest fixtures.

The suite runs against an in-memory SQLite database (a ``StaticPool`` keeps it
alive for the whole test) so it needs no PostgreSQL service and stays fast.
The portable ``JSONType`` in the models is what makes this possible.
"""

import os

# Must be set before anything imports app.core.config (settings are read once).
# A 48-byte key keeps PyJWT from warning about a short HMAC secret.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-pytest-only-0123456789abcdef")
os.environ.setdefault("ENVIRONMENT", "test")

from collections.abc import Callable, Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import Session, sessionmaker  # noqa: E402
from sqlalchemy.pool import StaticPool  # noqa: E402

import app.models  # noqa: E402, F401  -- register every table on Base.metadata
from app.api.deps import get_db  # noqa: E402
from app.crud import user as user_crud  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.main import app  # noqa: E402
from app.models.enums import Role  # noqa: E402
from app.models.user import User  # noqa: E402


@pytest.fixture
def db_session() -> Iterator[Session]:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    testing_session = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
    session = testing_session()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.fixture
def client(db_session: Session) -> Iterator[TestClient]:
    """A TestClient whose ``get_db`` dependency uses the in-memory session."""

    def override_get_db() -> Iterator[Session]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def make_user(db_session: Session) -> Callable[..., User]:
    """Factory creating a persisted user with a chosen role."""

    def _make(
        username: str = "alice",
        *,
        email: str | None = None,
        password: str = "password123",
        role: Role = Role.viewer,
    ) -> User:
        return user_crud.create_user(
            db_session,
            username=username,
            email=email or f"{username}@example.com",
            password=password,
            role=role,
        )

    return _make


@pytest.fixture
def auth_headers(client: TestClient) -> Callable[..., dict[str, str]]:
    """Log a user in and return an Authorization header for them."""

    def _headers(username: str, password: str = "password123") -> dict[str, str]:
        resp = client.post("/api/auth/login", data={"username": username, "password": password})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    return _headers
