# ruff: noqa: E402
import os
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from dotenv import dotenv_values

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent


def _load_env() -> None:
    values: dict[str, str] = {}
    for path in (REPO_ROOT / ".env", BACKEND_DIR / ".env"):
        if path.exists():
            values.update(
                {
                    key: value
                    for key, value in dotenv_values(path).items()
                    if value is not None
                }
            )

    test_database_url = os.environ.get("TEST_DATABASE_URL") or values.get(
        "TEST_DATABASE_URL"
    )
    if not test_database_url:
        raise RuntimeError("TEST_DATABASE_URL must be set to run the test suite.")

    os.environ["TEST_DATABASE_URL"] = test_database_url
    os.environ["DATABASE_URL"] = test_database_url
    os.environ.setdefault(
        "JWT_SECRET",
        values.get("JWT_SECRET") or "test-jwt-secret-not-for-production",
    )
    if "REDIS_URL" not in os.environ and "REDIS_URL" in values:
        os.environ["REDIS_URL"] = values["REDIS_URL"]


_load_env()

import psycopg
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.db.models import User, UserStatus
from app.db.session import SessionLocal, engine
from app.main import app


def _ensure_test_database() -> None:
    url = make_url(os.environ["TEST_DATABASE_URL"])
    database = url.database
    if not database:
        raise RuntimeError("TEST_DATABASE_URL must include a database name.")

    admin_url = url.set(drivername="postgresql", database="postgres")
    with psycopg.connect(
        admin_url.render_as_string(hide_password=False),
        autocommit=True,
    ) as connection:
        exists = connection.execute(
            "SELECT 1 FROM pg_database WHERE datname = %s",
            (database,),
        ).fetchone()
        if exists is None:
            connection.execute(f'CREATE DATABASE "{database}"')


@pytest.fixture(scope="session", autouse=True)
def _migrated_database() -> Iterator[None]:
    _ensure_test_database()
    config = Config(str(BACKEND_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    command.upgrade(config, "head")
    yield


def _truncate_tables() -> None:
    with engine.begin() as connection:
        connection.execute(
            text("TRUNCATE TABLE refresh_tokens, users RESTART IDENTITY CASCADE")
        )


@pytest.fixture(autouse=True)
def _clean_database(_migrated_database: None) -> Iterator[None]:
    _truncate_tables()
    yield
    _truncate_tables()


@pytest.fixture()
def db() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client() -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def make_user(db: Session) -> Callable[..., User]:
    def _make_user(
        email: str = "user@example.com",
        password: str = "Password123",
        *,
        display_name: str = "Test User",
        status: str = UserStatus.ACTIVE.value,
        is_platform_admin: bool = False,
        phone: str | None = None,
    ) -> User:
        user = User(
            email=email.lower(),
            password_hash=hash_password(password),
            display_name=display_name,
            phone=phone,
            status=status,
            is_platform_admin=is_platform_admin,
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        return user

    return _make_user


@pytest.fixture()
def login(client: TestClient) -> Callable[..., dict[str, Any]]:
    def _login(email: str, password: str = "Password123") -> dict[str, Any]:
        response = client.post(
            "/api/v1/auth/login",
            json={"email": email, "password": password},
        )
        assert response.status_code == 200, response.text
        return response.json()

    return _login
