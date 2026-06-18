"""Schemas for the authentication flow (JWT bearer tokens)."""

from pydantic import BaseModel

from app.models.enums import Role


class Token(BaseModel):
    """The bearer token returned on a successful login."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until expiry


class TokenPayload(BaseModel):
    """Decoded JWT claims. ``sub`` is the username, ``role`` drives RBAC."""

    sub: str
    role: Role
