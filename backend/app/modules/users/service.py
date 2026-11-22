import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.errors import AppError
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.db.models import RefreshToken, User, UserStatus
from app.modules.users.repository import RefreshTokensRepository, UsersRepository
from app.modules.users.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    RegisterRequest,
    TokenPair,
)


def _invalid_credentials() -> AppError:
    return AppError(401, "invalid_credentials", "Invalid email or password.")


def _normalize_detail(value: str) -> str:
    return " ".join(value.split()).casefold()


class AuthService:
    def __init__(self, db: Session) -> None:
        self.db = db
        self.users = UsersRepository(db)
        self.refresh_tokens = RefreshTokensRepository(db)

    def register(self, payload: RegisterRequest) -> User:
        if self.users.get_by_email(payload.email) is not None:
            raise AppError(
                409,
                "email_already_exists",
                "An account with this email already exists.",
            )

        user = User(
            email=payload.email.lower(),
            password_hash=hash_password(payload.password),
            display_name=payload.display_name,
            phone=payload.phone,
            status=UserStatus.ACTIVE.value,
            is_platform_admin=False,
        )
        self.users.add(user)
        try:
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            raise AppError(
                409,
                "email_already_exists",
                "An account with this email already exists.",
            ) from None

        self.db.refresh(user)
        return user

    def login(self, payload: LoginRequest) -> TokenPair:
        user = self.users.get_by_email(payload.email)
        if user is None:
            verify_password(payload.password, DUMMY_PASSWORD_HASH)
            raise _invalid_credentials()

        if not verify_password(payload.password, user.password_hash):
            raise _invalid_credentials()

        if user.status != UserStatus.ACTIVE:
            raise AppError(403, "account_disabled", "This account is disabled.")

        now = datetime.now(UTC)
        access_token, refresh_token = self._issue_pair(user.id, uuid.uuid4(), now)
        self.db.commit()
        return self._token_pair(access_token, refresh_token)

    def refresh(self, raw_refresh_token: str) -> TokenPair:
        now = datetime.now(UTC)
        stored = self.refresh_tokens.get_by_hash(
            hash_refresh_token(raw_refresh_token),
            for_update=True,
        )
        if stored is None:
            raise AppError(401, "invalid_refresh_token", "Invalid refresh token.")

        if stored.revoked_at is not None:
            self.refresh_tokens.revoke_family(stored.family_id, now)
            self.db.commit()
            raise AppError(
                401,
                "refresh_token_reused",
                "Refresh token has already been used.",
            )

        if stored.expires_at <= now:
            raise AppError(401, "refresh_token_expired", "Refresh token has expired.")

        user = self.users.get_by_id(stored.user_id)
        if user is None:
            raise AppError(401, "invalid_refresh_token", "Invalid refresh token.")
        if user.status != UserStatus.ACTIVE:
            raise AppError(403, "account_disabled", "This account is disabled.")

        stored.revoked_at = now
        access_token, refresh_token = self._issue_pair(user.id, stored.family_id, now)
        self.db.commit()
        return self._token_pair(access_token, refresh_token)

    def logout(self, raw_refresh_token: str) -> None:
        stored = self.refresh_tokens.get_by_hash(hash_refresh_token(raw_refresh_token))
        if stored is None:
            return
        self.refresh_tokens.revoke_family(stored.family_id, datetime.now(UTC))
        self.db.commit()

    def forgot_password(self, payload: ForgotPasswordRequest) -> None:
        user = self.users.get_by_email(payload.email)
        if (
            user is None
            or user.status != UserStatus.ACTIVE
            or _normalize_detail(user.display_name)
            != _normalize_detail(payload.display_name)
        ):
            raise AppError(
                400,
                "invalid_reset_details",
                "Invalid account details.",
            )

        user.password_hash = hash_password(payload.new_password)
        self.refresh_tokens.revoke_all_for_user(user.id, datetime.now(UTC))
        self.db.commit()

    def _issue_pair(
        self,
        user_id: uuid.UUID,
        family_id: uuid.UUID,
        now: datetime,
    ) -> tuple[str, str]:
        access_token = create_access_token(user_id, now=now)
        raw_refresh_token = generate_refresh_token()
        self.refresh_tokens.add(
            RefreshToken(
                user_id=user_id,
                family_id=family_id,
                token_hash=hash_refresh_token(raw_refresh_token),
                expires_at=now + timedelta(days=settings.refresh_token_days),
            )
        )
        return access_token, raw_refresh_token

    @staticmethod
    def _token_pair(access_token: str, refresh_token: str) -> TokenPair:
        return TokenPair(
            access_token=access_token,
            refresh_token=refresh_token,
            expires_in=settings.access_token_minutes * 60,
        )
