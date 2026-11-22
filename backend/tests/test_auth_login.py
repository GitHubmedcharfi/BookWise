from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import security
from app.db.models import RefreshToken, User, UserStatus

LOGIN_URL = "/api/v1/auth/login"


def test_login_returns_token_pair_and_stores_only_hash(
    client: TestClient,
    make_user: Callable[..., User],
    db: Session,
) -> None:
    user = make_user(email="alice@example.com")

    response = client.post(
        LOGIN_URL,
        json={"email": "ALICE@example.com", "password": "Password123"},
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 900
    assert body["access_token"]
    assert body["refresh_token"]

    payload = security.decode_access_token(body["access_token"])
    assert payload["sub"] == str(user.id)

    stored = db.scalar(select(RefreshToken))
    assert stored is not None
    assert stored.token_hash == security.hash_refresh_token(body["refresh_token"])
    assert stored.token_hash != body["refresh_token"]
    assert stored.user_id == user.id
    assert stored.revoked_at is None


def test_login_unknown_email_and_wrong_password_are_identical(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    make_user(email="alice@example.com")

    wrong_password = client.post(
        LOGIN_URL,
        json={"email": "alice@example.com", "password": "WrongPassword1"},
    )
    unknown_email = client.post(
        LOGIN_URL,
        json={"email": "nobody@example.com", "password": "WrongPassword1"},
    )

    assert wrong_password.status_code == 401
    assert unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()
    assert wrong_password.json()["error"]["code"] == "invalid_credentials"


def test_login_disabled_account(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    make_user(email="alice@example.com", status=UserStatus.DISABLED.value)

    response = client.post(
        LOGIN_URL,
        json={"email": "alice@example.com", "password": "Password123"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "account_disabled"


def test_login_disabled_account_with_wrong_password_is_401(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    make_user(email="alice@example.com", status=UserStatus.DISABLED.value)

    response = client.post(
        LOGIN_URL,
        json={"email": "alice@example.com", "password": "WrongPassword1"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_credentials"
