"""Admin-only user management. Every route here requires the admin role."""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import CurrentUser, require_min_role
from app.crud import user as user_crud
from app.db.session import get_db
from app.models.enums import Role
from app.schemas.user import RoleUpdate, UserCreate, UserRead

router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(require_min_role(Role.admin))],
)

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[UserRead])
def list_users(db: DbSession) -> list[UserRead]:
    return [UserRead.model_validate(u) for u in user_crud.list_users(db)]


@router.post("", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, db: DbSession) -> UserRead:
    """Create a user with an explicit role (admin/analyst/viewer)."""
    if user_crud.get_user_by_username(db, payload.username):
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already taken.")
    if user_crud.get_user_by_email(db, payload.email):
        raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered.")
    user = user_crud.create_user(
        db,
        username=payload.username,
        email=payload.email,
        password=payload.password,
        role=payload.role,
    )
    return UserRead.model_validate(user)


@router.patch("/{user_id}/role", response_model=UserRead)
def update_role(
    user_id: int,
    payload: RoleUpdate,
    db: DbSession,
    current_user: CurrentUser,
) -> UserRead:
    """Change a user's role. An admin cannot change their own role — this
    prevents accidentally locking the last administrator out of the system."""
    user = user_crud.get_user(db, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found.")
    if user.id == current_user.id:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "You cannot change your own role.",
        )
    updated = user_crud.set_role(db, user, payload.role)
    return UserRead.model_validate(updated)
