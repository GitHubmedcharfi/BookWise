import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import security
from app.db.models import RefreshToken, User, UserStatus

REFRESH_URL = "/api/v1/auth/refresh"


def _refresh(client: TestClient, token: str) -> object:
    return client.post(REFRESH_URL, json={"refresh_token": token})


def test_refresh_rotates_tokens(
    client: TestClient,
    make_user: Callable[..., User],
    login: Callable[..., dict[str, object]],
    db: Session,
) -> None:
    make_user(email="alice@example.com")
    first = login("alice@example.com")

    response = _refresh(client, str(first["refresh_token"]))

    assert response.status_code == 200, response.text
    second = response.json()
    assert second["refresh_token"] != first["refresh_token"]
    assert second["access_token"] != first["access_token"]
    assert second["token_type"] == "bearer"
    assert second["expires_in"] == 900

    old = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash
            == security.hash_refresh_token(str(first["refresh_token"]))
        )
    )
    assert old is not None
    assert old.revoked_at is not None

    newer = db.scalar(
        select(RefreshToken).where(
            RefreshToken.token_hash
            == security.hash_refresh_token(str(second["refresh_token"]))
        )
    )
    assert newer is not None
    assert newer.family_id == old.family_id
    assert newer.revoked_at is None


def test_refresh_reuse_revokes_whole_family(
    client: TestClient,
    make_user: Callable[..., User],
    login: Callable[..., dict[str, object]],
    db: Session,
) -> None:
    make_user(email="alice@example.com")
    first = login("alice@example.com")
    second = _refresh(client, str(first["refresh_token"])).json()

    reused = _refresh(client, str(first["refresh_token"]))
    newer = _refresh(client, str(second["refresh_token"]))

    assert reused.status_code == 401
    assert reused.json()["error"]["code"] == "refresh_token_reused"
    assert newer.status_code == 401

    stored = db.scalars(select(RefreshToken)).all()
    assert stored
    assert all(token.revoked_at is not None for token in stored)


def test_refresh_unknown_token(client: TestClient) -> None:
    response = _refresh(client, "not-a-real-token")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_refresh_token"


def test_refresh_expired_token(
    client: TestClient,
    make_user: Callable[..., User],
    db: Session,
) -> None:
    user = make_user()
    raw_token = "expired-refresh-token"
    db.add(
        RefreshToken(
            user_id=user.id,
            family_id=uuid.uuid4(),
            token_hash=security.hash_refresh_token(raw_token),
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        )
    )
    db.commit()

    response = _refresh(client, raw_token)

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "refresh_token_expired"


def test_refresh_disabled_user(
    client: TestClient,
    make_user: Callable[..., User],
    login: Callable[..., dict[str, object]],
    db: Session,
) -> None:
    user = make_user(email="alice@example.com")
    tokens = login("alice@example.com")

    user.status = UserStatus.DISABLED.value
    db.commit()

    response = _refresh(client, str(tokens["refresh_token"]))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "account_disabled"
