import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import jwt
import pytest

from app.core import security
from app.core.config import settings
from app.core.deps import require_platform_admin
from app.core.errors import AppError


def test_password_hash_and_verify() -> None:
    hashed = security.hash_password("Password123")

    assert hashed != "Password123"
    assert hashed.startswith("$argon2")
    assert security.verify_password("Password123", hashed)
    assert not security.verify_password("WrongPassword1", hashed)
    assert not security.verify_password("Password123", "not-a-valid-hash")


def test_access_token_roundtrip() -> None:
    user_id = uuid.uuid4()

    payload = security.decode_access_token(security.create_access_token(user_id))

    assert payload["sub"] == str(user_id)
    assert payload["type"] == "access"
    assert payload["jti"]
    assert payload["iat"] <= payload["exp"]


def test_expired_access_token() -> None:
    token = security.create_access_token(
        uuid.uuid4(),
        now=datetime.now(UTC) - timedelta(hours=2),
    )

    with pytest.raises(security.TokenExpiredError):
        security.decode_access_token(token)


def test_tampered_access_token() -> None:
    token = security.create_access_token(uuid.uuid4())
    header, payload, signature = token.split(".")
    tampered = ".".join(
        [header, ("A" if payload[0] != "A" else "B") + payload[1:], signature]
    )

    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(tampered)


def test_token_forged_with_another_secret() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
        },
        "another-secret-that-is-long-enough-for-hs256",
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_token_with_wrong_type_is_rejected() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": "refresh",
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_token_without_required_claims_is_rejected() -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "type": "access",
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(security.InvalidTokenError):
        security.decode_access_token(token)


def test_refresh_token_hash_is_deterministic_and_not_raw() -> None:
    raw = security.generate_refresh_token()

    first = security.hash_refresh_token(raw)
    second = security.hash_refresh_token(raw)

    assert first == second
    assert first != raw
    assert len(first) == 64
    assert security.generate_refresh_token() != raw


def test_require_platform_admin() -> None:
    admin = SimpleNamespace(is_platform_admin=True)
    regular_user = SimpleNamespace(is_platform_admin=False)

    assert require_platform_admin(admin) is admin

    with pytest.raises(AppError) as exc_info:
        require_platform_admin(regular_user)

    assert exc_info.value.status_code == 403
    assert exc_info.value.code == "forbidden"
