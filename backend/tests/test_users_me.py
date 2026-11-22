import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import jwt
from fastapi.testclient import TestClient

from app.core import security
from app.core.config import settings
from app.db.models import User, UserStatus

ME_URL = "/api/v1/users/me"


def test_me_requires_authentication(client: TestClient) -> None:
    response = client.get(ME_URL)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"
    assert response.headers["WWW-Authenticate"] == "Bearer"


def test_me_returns_current_user(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    user = make_user(email="alice@example.com", display_name="Alice")
    token = security.create_access_token(user.id)

    response = client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == str(user.id)
    assert body["email"] == "alice@example.com"
    assert body["display_name"] == "Alice"
    assert "password_hash" not in body


def test_me_rejects_expired_token(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    user = make_user()
    token = security.create_access_token(
        user.id,
        now=datetime.now(UTC) - timedelta(hours=2),
    )

    response = client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "token_expired"


def test_me_rejects_garbage_token(client: TestClient) -> None:
    response = client.get(ME_URL, headers={"Authorization": "Bearer garbage"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"


def test_me_rejects_disabled_users_token(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    user = make_user(status=UserStatus.DISABLED.value)
    token = security.create_access_token(user.id)

    response = client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"


def test_me_rejects_token_with_non_uuid_subject(client: TestClient) -> None:
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": "not-a-uuid",
            "type": "access",
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    response = client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"


def test_me_rejects_refresh_token_type(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    user = make_user()
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(user.id),
            "type": "refresh",
            "jti": uuid.uuid4().hex,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=15)).timestamp()),
        },
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    response = client.get(ME_URL, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"
