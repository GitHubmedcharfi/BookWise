from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from app.core.deps import CurrentUser
from app.db.models import User
from app.db.session import get_db
from app.modules.users.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    RefreshTokenRequest,
    RegisterRequest,
    TokenPair,
    UserRead,
)
from app.modules.users.service import AuthService

DbSession = Annotated[Session, Depends(get_db)]

auth_router = APIRouter()
users_router = APIRouter()


@auth_router.post(
    "/register",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def register(payload: RegisterRequest, db: DbSession) -> User:
    return AuthService(db).register(payload)


@auth_router.post("/login", response_model=TokenPair)
def login(payload: LoginRequest, db: DbSession) -> TokenPair:
    return AuthService(db).login(payload)


@auth_router.post("/forgot-password", status_code=status.HTTP_204_NO_CONTENT)
def forgot_password(payload: ForgotPasswordRequest, db: DbSession) -> Response:
    AuthService(db).forgot_password(payload)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@auth_router.post("/refresh", response_model=TokenPair)
def refresh(payload: RefreshTokenRequest, db: DbSession) -> TokenPair:
    return AuthService(db).refresh(payload.refresh_token)


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(payload: RefreshTokenRequest, db: DbSession) -> Response:
    AuthService(db).logout(payload.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@users_router.get("/me", response_model=UserRead)
def read_current_user(current_user: CurrentUser) -> User:
    return current_user
