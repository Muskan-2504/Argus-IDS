"""Tests for the admin-bootstrap CLI helper."""

import pytest
from sqlalchemy.orm import Session

from app.cli import create_admin_user
from app.models.enums import Role


def test_create_admin_user(db_session: Session) -> None:
    user = create_admin_user(
        db_session, username="root", email="root@argus.local", password="password123"
    )
    assert user.role is Role.admin
    assert user.hashed_password != "password123"  # stored as a hash


def test_create_admin_user_rejects_duplicate(db_session: Session) -> None:
    create_admin_user(db_session, username="root", email="a@b.c", password="password123")
    with pytest.raises(ValueError, match="already exists"):
        create_admin_user(db_session, username="root", email="x@y.z", password="password123")
