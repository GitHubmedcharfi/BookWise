import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import verify_password
from app.db.models import User
from app.modules.users.repository import UsersRepository

REGISTER_URL = "/api/v1/auth/register"


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "email": "Alice@Example.com",
        "password": "Password123",
        "display_name": "Alice",
    }
    payload.update(overrides)
    return payload


def test_register_success(client: TestClient, db: Session) -> None:
    response = client.post(REGISTER_URL, json=_payload())

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["email"] == "alice@example.com"
    assert body["is_platform_admin"] is False
    assert "password_hash" not in body
    assert "password" not in body

    user = db.scalar(select(User).where(User.email == "alice@example.com"))
    assert user is not None
    assert user.password_hash != "Password123"
    assert user.password_hash.startswith("$argon2")
    assert verify_password("Password123", user.password_hash)


def test_register_duplicate_email_is_case_insensitive(client: TestClient) -> None:
    assert client.post(REGISTER_URL, json=_payload()).status_code == 201

    response = client.post(REGISTER_URL, json=_payload(email="ALICE@EXAMPLE.COM"))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "email_already_exists"


def test_register_duplicate_race_returns_409(
    client: TestClient,
    make_user: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    make_user(email="alice@example.com")
    monkeypatch.setattr(UsersRepository, "get_by_email", lambda self, email: None)

    response = client.post(REGISTER_URL, json=_payload(email="alice@example.com"))

    assert response.status_code == 409
    assert response.json()["error"]["code"] == "email_already_exists"


@pytest.mark.parametrize(
    "overrides",
    [
        {"email": "not-an-email"},
        {"password": "Ab1"},
        {"password": "PasswordOnly"},
        {"password": "12345678"},
        {"display_name": "   "},
    ],
)
def test_register_validation_errors(
    client: TestClient,
    overrides: dict[str, object],
) -> None:
    response = client.post(REGISTER_URL, json=_payload(**overrides))

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_validation_error_does_not_echo_password(client: TestClient) -> None:
    password = "S3cr3t"

    response = client.post(REGISTER_URL, json=_payload(password=password))

    assert response.status_code == 422
    assert password not in response.text


def test_register_stores_phone_and_normalizes_blank_phone(
    client: TestClient,
) -> None:
    with_phone = client.post(REGISTER_URL, json=_payload(phone=" +1 555 0100 "))
    blank_phone = client.post(
        REGISTER_URL,
        json=_payload(email="bob@example.com", phone="   "),
    )

    assert with_phone.status_code == 201
    assert with_phone.json()["phone"] == "+1 555 0100"
    assert blank_phone.status_code == 201
    assert blank_phone.json()["phone"] is None


def test_client_cannot_set_platform_admin(
    client: TestClient,
    db: Session,
) -> None:
    response = client.post(REGISTER_URL, json=_payload(is_platform_admin=True))

    assert response.status_code == 201
    assert response.json()["is_platform_admin"] is False

    user = db.scalar(select(User).where(User.email == "alice@example.com"))
    assert user is not None
    assert user.is_platform_admin is False
