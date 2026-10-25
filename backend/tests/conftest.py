from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from collections.abc import Callable, Iterator
from pathlib import Path

import httpx
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("MAKKADI_DATA_DIR", tempfile.mkdtemp(prefix="makkadi-test-"))
os.environ["MAKKADI_WORKER_ENABLED"] = "false"
os.environ["MAKKADI_ENVIRONMENT"] = "test"
os.environ["MAKKADI_DEMO_MODE"] = "true"
os.environ["MAKKADI_AI_PROVIDER"] = "deterministic"

from fastapi.testclient import TestClient  # noqa: E402

from app.connectors.http import set_transport  # noqa: E402
from app.core.config import get_settings  # noqa: E402
from app.database.session import SessionLocal  # noqa: E402
from app.security.ratelimit import limiter  # noqa: E402
from app.security.ssrf import set_resolver  # noqa: E402

ADMIN = ("admin", "Adm1nistrateur-Test")
PUBLIC_IP = "93.184.215.14"


@pytest.fixture
def env(tmp_path, monkeypatch) -> Iterator[Path]:
    monkeypatch.setenv("MAKKADI_DATA_DIR", str(tmp_path))
    get_settings.cache_clear()
    limiter.reset()
    set_resolver(lambda host: [PUBLIC_IP])
    yield tmp_path
    set_transport(None)
    set_resolver(None)
    get_settings.cache_clear()


@pytest.fixture
def client(env) -> Iterator[TestClient]:
    from app.main import app

    with TestClient(app, client=("127.0.0.1", 50000)) as c:
        yield c


@pytest.fixture
def db(client):  # noqa: ANN001
    with SessionLocal() as session:
        yield session


def auth_headers(client: TestClient, username: str, password: str) -> dict[str, str]:
    r = client.post("/api/v1/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture
def admin(client) -> dict[str, str]:  # noqa: ANN001
    r = client.post("/api/v1/auth/bootstrap", json={"username": ADMIN[0], "password": ADMIN[1]})
    assert r.status_code == 201, r.text
    return auth_headers(client, *ADMIN)


def create_user(client: TestClient, admin_h: dict, username: str, role: str) -> dict[str, str]:
    password = "Utilisateur-Test-42"
    r = client.post("/api/v1/users", headers=admin_h, json={"username": username, "password": password, "role": role})
    assert r.status_code == 201, r.text
    return auth_headers(client, username, password)


def drain() -> int:
    from app.services.tasks import drain as _drain

    return asyncio.run(_drain(SessionLocal))


@pytest.fixture
def mock_http() -> Callable[[Callable[[httpx.Request], httpx.Response]], None]:
    def install(handler: Callable[[httpx.Request], httpx.Response]) -> None:
        set_transport(httpx.MockTransport(handler))

    yield install
    set_transport(None)
