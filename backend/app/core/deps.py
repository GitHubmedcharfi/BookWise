import uuid
from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core import security
from app.core.errors import AppError
from app.db.models import User, UserStatus
from app.db.session import get_db

bearer_scheme = HTTPBearer(auto_error=False)
WWW_AUTHENTICATE = {"WWW-Authenticate": "Bearer"}


def _unauthorized(code: str, message: str) -> AppError:
    return AppError(401, code, message, headers=WWW_AUTHENTICATE)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    if credentials is None or not credentials.credentials:
        raise _unauthorized("not_authenticated", "Authentication required.")

    try:
        payload = security.decode_access_token(credentials.credentials)
    except security.TokenExpiredError:
        raise _unauthorized("token_expired", "Access token has expired.") from None
    except security.InvalidTokenError:
        raise _unauthorized("invalid_token", "Invalid access token.") from None

    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (KeyError, ValueError, TypeError):
        raise _unauthorized("invalid_token", "Invalid access token.") from None

    user = db.get(User, user_id)
    if user is None or user.status != UserStatus.ACTIVE:
        raise _unauthorized("invalid_token", "Invalid access token.")
    return user


def require_platform_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    if not current_user.is_platform_admin:
        raise AppError(
            403,
            "forbidden",
            "Platform administrator access required.",
        )
    return current_user


CurrentUser = Annotated[User, Depends(get_current_user)]
PlatformAdmin = Annotated[User, Depends(require_platform_admin)]
