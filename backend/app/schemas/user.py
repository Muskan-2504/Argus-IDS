"""Request/response schemas for users.

Two creation paths exist on purpose:

* :class:`UserRegister` is what the public ``/auth/register`` endpoint
  accepts. It carries **no role**, so a self-registered account can never
  grant itself anything beyond the default ``viewer`` — this closes the
  privilege-escalation hole that open registration would otherwise create.
* :class:`UserCreate` adds an explicit ``role`` and is only reachable through
  the admin-only user-management endpoint.
"""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models.enums import Role

USERNAME_PATTERN = r"^[A-Za-z0-9_.-]+$"


class UserRegister(BaseModel):
    """Public self-registration payload (always becomes a ``viewer``)."""

    username: str = Field(min_length=3, max_length=50, pattern=USERNAME_PATTERN)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class UserCreate(UserRegister):
    """Admin-only creation payload that may assign any role."""

    role: Role = Role.viewer


class UserRead(BaseModel):
    """Safe user representation — never exposes the password hash."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: EmailStr
    role: Role
    is_active: bool
    created_at: datetime
    last_login: datetime | None = None


class RoleUpdate(BaseModel):
    """Admin changing another account's role."""

    role: Role
