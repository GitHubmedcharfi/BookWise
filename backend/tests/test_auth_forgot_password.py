from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.db.models import User, UserStatus

FORGOT_PASSWORD_URL = "/api/v1/auth/forgot-password"
LOGIN_URL = "/api/v1/auth/login"
REFRESH_URL = "/api/v1/auth/refresh"


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "email": "alice@example.com",
        "display_name": "Alice Smith",
        "new_password": "NewPassword123",
    }
    payload.update(overrides)
    return payload


def test_forgot_password_resets_with_matching_display_name(
    client: TestClient,
    make_user: Callable[..., User],
    login: Callable[..., dict[str, object]],
    db: Session,
) -> None:
    user = make_user(email="alice@example.com", display_name="Alice Smith")
    tokens = login("alice@example.com")

    response = client.post(
        FORGOT_PASSWORD_URL,
        json=_payload(display_name="  alice   smith "),
    )

    assert response.status_code == 204, response.text
    assert response.content == b""

    db.refresh(user)
    assert verify_password("NewPassword123", user.password_hash)
    assert not verify_password("Password123", user.password_hash)

    old_login = client.post(
        LOGIN_URL,
        json={"email": "alice@example.com", "password": "Password123"},
    )
    new_login = client.post(
        LOGIN_URL,
        json={"email": "alice@example.com", "password": "NewPassword123"},
    )
    assert old_login.status_code == 401
    assert new_login.status_code == 200

    refresh = client.post(
        REFRESH_URL,
        json={"refresh_token": tokens["refresh_token"]},
    )
    assert refresh.status_code == 401


def test_forgot_password_rejects_mismatched_display_name(
    client: TestClient,
    make_user: Callable[..., User],
    db: Session,
) -> None:
    user = make_user(email="alice@example.com", display_name="Alice Smith")

    response = client.post(
        FORGOT_PASSWORD_URL,
        json=_payload(display_name="Alice"),
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_reset_details"

    db.refresh(user)
    assert verify_password("Password123", user.password_hash)


def test_forgot_password_unknown_email_and_bad_detail_are_identical(
    client: TestClient,
    make_user: Callable[..., User],
) -> None:
    make_user(email="alice@example.com", display_name="Alice Smith")

    wrong_detail = client.post(
        FORGOT_PASSWORD_URL,
        json=_payload(display_name="Someone Else"),
    )
    unknown_email = client.post(
        FORGOT_PASSWORD_URL,
        json=_payload(email="nobody@example.com"),
    )

    assert wrong_detail.status_code == 400
    assert unknown_email.status_code == 400
    assert wrong_detail.json() == unknown_email.json()


def test_forgot_password_rejects_disabled_account(
    client: TestClient,
    make_user: Callable[..., User],
    db: Session,
) -> None:
    user = make_user(
        email="alice@example.com",
        display_name="Alice Smith",
        status=UserStatus.DISABLED.value,
    )

    response = client.post(FORGOT_PASSWORD_URL, json=_payload())

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_reset_details"

    db.refresh(user)
    assert verify_password("Password123", user.password_hash)


@pytest.mark.parametrize(
    "overrides",
    [
        {"email": "not-an-email"},
        {"display_name": "   "},
        {"new_password": "Ab1"},
        {"new_password": "PasswordOnly"},
        {"new_password": "12345678"},
    ],
)
def test_forgot_password_validation_errors(
    client: TestClient,
    overrides: dict[str, object],
) -> None:
    response = client.post(FORGOT_PASSWORD_URL, json=_payload(**overrides))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
