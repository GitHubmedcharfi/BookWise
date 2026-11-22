import argparse
import sys

from pydantic import ValidationError

from app.core.security import hash_password
from app.db.models import User, UserStatus
from app.db.session import SessionLocal
from app.modules.users.repository import UsersRepository
from app.modules.users.schemas import RegisterRequest


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create (or promote) the first BookWise platform admin.",
    )
    parser.add_argument("email")
    parser.add_argument("password")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        payload = RegisterRequest(
            email=args.email,
            password=args.password,
            display_name="Platform Admin",
        )
    except ValidationError:
        print(
            "Invalid email or password. The password must be 8-128 characters "
            "and contain at least one letter and one digit.",
            file=sys.stderr,
        )
        return 1

    with SessionLocal() as db:
        users = UsersRepository(db)
        user = users.get_by_email(payload.email)
        if user is None:
            user = User(
                email=payload.email,
                password_hash=hash_password(payload.password),
                display_name="Platform Admin",
                status=UserStatus.ACTIVE.value,
                is_platform_admin=True,
            )
            users.add(user)
            db.commit()
            print(f"Created platform admin {payload.email}.")
            return 0

        user.is_platform_admin = True
        db.commit()
        print(f"Existing user {payload.email} is now a platform admin.")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
