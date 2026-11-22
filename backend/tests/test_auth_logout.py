from collections.abc import Callable

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import RefreshToken, User

LOGOUT_URL = "/api/v1/auth/logout"
REFRESH_URL = "/api/v1/auth/refresh"


def _refresh(client: TestClient, token: str) -> object:
    return client.post(REFRESH_URL, json={"refresh_token": token})


def test_logout_revokes_token(
    client: TestClient,
    make_user: Callable[..., User],
    login: Callable[..., dict[str, object]],
    db: Session,
) -> None:
    make_user(email="alice@example.com")
    tokens = login("alice@example.com")

    response = client.post(
        LOGOUT_URL,
        json={"refresh_token": tokens["refresh_token"]},
    )

    assert response.status_code == 204
    assert response.content == b""
    assert _refresh(client, str(tokens["refresh_token"])).status_code == 401

    stored = db.scalar(select(RefreshToken))
    assert stored is not None
    assert stored.revoked_at is not None


def test_logout_is_idempotent(
    client: TestClient,
    make_user: Callable[..., User],
    login: Callable[..., dict[str, object]],
) -> None:
    make_user(email="alice@example.com")
    tokens = login("alice@example.com")

    first = client.post(LOGOUT_URL, json={"refresh_token": tokens["refresh_token"]})
    second = client.post(LOGOUT_URL, json={"refresh_token": tokens["refresh_token"]})

    assert first.status_code == 204
    assert second.status_code == 204


def test_logout_with_unknown_token_still_returns_204(client: TestClient) -> None:
    response = client.post(LOGOUT_URL, json={"refresh_token": "does-not-exist"})

    assert response.status_code == 204


def test_logout_only_ends_that_session(
    client: TestClient,
    make_user: Callable[..., User],
    login: Callable[..., dict[str, object]],
) -> None:
    make_user(email="alice@example.com")
    first_session = login("alice@example.com")
    second_session = login("alice@example.com")

    response = client.post(
        LOGOUT_URL,
        json={"refresh_token": first_session["refresh_token"]},
    )

    assert response.status_code == 204
    assert _refresh(client, str(first_session["refresh_token"])).status_code == 401
    assert _refresh(client, str(second_session["refresh_token"])).status_code == 200
