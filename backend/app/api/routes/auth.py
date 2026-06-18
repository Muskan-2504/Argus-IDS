"""Authentication endpoints: register, login, and 'who am I'."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser
from app.core.config import settings
from app.core.security import create_access_token
from app.crud import user as user_crud
from app.db.session import get_db
from app.schemas.auth import Token
from app.schemas.user import UserRead, UserRegister

router = APIRouter(prefix="/auth", tags=["auth"])

DbSession = Annotated[Session, Depends(get_db)]


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(payload: UserRegister, db: DbSession) -> UserRead:
    """Self-service registration. New accounts always start as ``viewer``."""
    if user_crud.get_user_by_username(db, payload.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken.")
    if user_crud.get_user_by_email(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered.")
    user = user_crud.create_user(
        db,
        username=payload.username,
        email=payload.email,
        password=payload.password,
    )
    return UserRead.model_validate(user)


@router.post("/login", response_model=Token)
def login(form: Annotated[OAuth2PasswordRequestForm, Depends()], db: DbSession) -> Token:
    """Exchange username + password for a signed JWT (OAuth2 password flow)."""
    user = user_crud.authenticate(db, form.username, form.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user_crud.touch_last_login(db, user)
    token = create_access_token(subject=user.username, role=user.role.value)
    return Token(access_token=token, expires_in=settings.access_token_expire_minutes * 60)


@router.get("/me", response_model=UserRead)
def me(current_user: CurrentUser) -> UserRead:
    """Return the profile of the currently authenticated user."""
    return UserRead.model_validate(current_user)
