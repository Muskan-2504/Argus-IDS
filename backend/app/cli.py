"""Command-line admin utilities.

Bootstraps the first administrator, since self-registration only ever creates
``viewer`` accounts. Run after the database is migrated::

    python -m app.cli create-admin --username admin --email admin@argus.local --password '...'
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from sqlalchemy.orm import Session

from app.crud import user as user_crud
from app.db.session import SessionLocal
from app.models.enums import Role
from app.models.user import User


def create_admin_user(db: Session, *, username: str, email: str, password: str) -> User:
    """Create an admin account. Raises ``ValueError`` if the name is taken."""
    if user_crud.get_user_by_username(db, username):
        raise ValueError(f"User '{username}' already exists.")
    return user_crud.create_user(
        db, username=username, email=email, password=password, role=Role.admin
    )


def _cmd_create_admin(args: argparse.Namespace) -> int:
    db = SessionLocal()
    try:
        user = create_admin_user(
            db, username=args.username, email=args.email, password=args.password
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()
    print(f"Created admin '{user.username}' (id={user.id}).")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="argus", description="Argus admin utilities.")
    sub = parser.add_subparsers(dest="command", required=True)

    create = sub.add_parser("create-admin", help="Create the bootstrap admin user.")
    create.add_argument("--username", required=True)
    create.add_argument("--email", required=True)
    create.add_argument("--password", required=True)
    create.set_defaults(func=_cmd_create_admin)

    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
