"""Reusable FastAPI dependencies for authentication and RBAC.

``get_current_user`` turns a bearer token into a ``User`` (or 401).
``require_min_role`` is a dependency *factory* enforcing the role hierarchy

    viewer (read) < analyst (ingest/triage) < admin (manage users)

so a route can simply declare ``Depends(require_min_role(Role.analyst))``.
"""

from collections.abc import Callable
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.core.security import decode_access_token
from app.crud import user as user_crud
from app.db.session import get_db
from app.models.enums import Role
from app.models.user import User
from app.schemas.auth import TokenPayload

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# Higher number = more privilege. Used to compare against a route's minimum.
_ROLE_RANK: dict[Role, int] = {Role.viewer: 1, Role.analyst: 2, Role.admin: 3}


def _credentials_exception() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Decode the bearer token and load the matching active user."""
    try:
        payload = decode_access_token(token)
        token_data = TokenPayload.model_validate(payload)
    except (jwt.PyJWTError, ValidationError) as exc:
        raise _credentials_exception() from exc

    user = user_crud.get_user_by_username(db, token_data.sub)
    if user is None or not user.is_active:
        raise _credentials_exception()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_min_role(min_role: Role) -> Callable[[User], User]:
    """Build a dependency that allows only users at or above ``min_role``."""

    def checker(user: CurrentUser) -> User:
        if _ROLE_RANK[user.role] < _ROLE_RANK[min_role]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the '{min_role}' role or higher.",
            )
        return user

    return checker
