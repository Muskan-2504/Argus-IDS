"""User persistence and authentication helpers."""

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password
from app.models.enums import Role
from app.models.user import User


def get_user(db: Session, user_id: int) -> User | None:
    return db.get(User, user_id)


def get_user_by_username(db: Session, username: str) -> User | None:
    return db.scalar(select(User).where(User.username == username))


def get_user_by_email(db: Session, email: str) -> User | None:
    return db.scalar(select(User).where(User.email == email))


def list_users(db: Session) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


def create_user(
    db: Session,
    *,
    username: str,
    email: str,
    password: str,
    role: Role = Role.viewer,
) -> User:
    """Create a user, storing only the Argon2id hash of the password."""
    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def set_role(db: Session, user: User, role: Role) -> User:
    user.role = role
    db.commit()
    db.refresh(user)
    return user


def authenticate(db: Session, username: str, password: str) -> User | None:
    """Return the user iff the password is correct and the account is active."""
    user = get_user_by_username(db, username)
    if user is None or not user.is_active:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def touch_last_login(db: Session, user: User) -> None:
    user.last_login = datetime.now(UTC)
    db.commit()
