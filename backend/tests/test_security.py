import sqlite3
import time

import pytest
from sqlalchemy import select

from app.core.errors import OutboundBlocked
from app.models import AuditLog, ConnectorConfig
from app.security.ssrf import set_resolver, validate_outbound_url
from app.security.webhook import compute_signature
from tests.conftest import ADMIN, auth_headers, create_user, drain

API = "/api/v1"


@pytest.mark.parametrize("url", [
    "http://example.org/", "https://127.0.0.1/", "https://10.0.0.1/x", "https://169.254.169.254/latest/meta-data",
    "https://[::1]/", "https://user:pass@example.org/", "file:///etc/passwd", "gopher://x/", "https://0.0.0.0/",
    "https://[::ffff:127.0.0.1]/",
])
def test_ssrf_blocked(env, url):
    with pytest.raises(OutboundBlocked):
        validate_outbound_url(url)


def test_ssrf_dns_to_private_blocked_and_allowlist(env, monkeypatch):
    set_resolver(lambda host: ["10.0.0.8"])
    with pytest.raises(OutboundBlocked):
        validate_outbound_url("https://siem.corp.example/")
    monkeypatch.setenv("MAKKADI_OUTBOUND_ALLOWED_HOSTS", '["siem.corp.example"]')
    from app.core.config import get_settings

    get_settings.cache_clear()
    assert validate_outbound_url("https://siem.corp.example/")


def test_authentication_required(client):
    for path in ("/investigations", "/dashboard", "/connectors", "/audit", "/settings", "/reports", "/tasks"):
        assert client.get(API + path).status_code == 401
    assert client.get(API + "/investigations", headers={"Authorization": "Bearer forged.token.value"}).status_code == 401


def test_bootstrap_only_once_and_local_only(client):
    assert client.get(API + "/auth/setup-status").json()["needs_setup"] is True
    weak = client.post(API + "/auth/bootstrap", json={"username": "admin", "password": "short"})
    assert weak.status_code == 422
    assert client.post(API + "/auth/bootstrap", json={"username": ADMIN[0], "password": ADMIN[1]}).status_code == 201
    assert client.post(API + "/auth/bootstrap", json={"username": "second", "password": ADMIN[1]}).status_code == 409


def test_bootstrap_refused_remotely(env):
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app, client=("203.0.113.5", 1234)) as c:
        assert c.post(API + "/auth/bootstrap", json={"username": "admin", "password": ADMIN[1]}).status_code == 403


def test_rbac(client, admin):
    viewer = create_user(client, admin, "lecteur", "viewer")
    analyst = create_user(client, admin, "analyste", "analyst")
    assert client.post(API + "/ingest/demo", headers=viewer).status_code == 403
    assert client.get(API + "/users", headers=analyst).status_code == 403
    assert client.post(API + "/connectors", headers=analyst, json={"kind": "osint", "provider": "virustotal", "name": "vt2"}).status_code == 403
    assert client.put(API + "/settings/scoring", headers=analyst, json={"value": {}}).status_code == 403
    assert client.get(API + "/investigations", headers=viewer).status_code == 200


def test_restricted_investigation_isolation(client, admin):
    a1 = create_user(client, admin, "analyste1", "analyst")
    a2 = create_user(client, admin, "analyste2", "analyst")
    client.post(API + "/ingest/demo", headers=a1)
    drain()
    inv = client.get(API + "/investigations", headers=a1).json()["items"][0]
    assert client.patch(API + f"/investigations/{inv['id']}", headers=a1, json={"restricted": True}).status_code == 200
    # a2 cannot see it (404, no existence oracle), list hides it, reports hidden
    assert client.get(API + f"/investigations/{inv['id']}", headers=a2).status_code == 404
    assert inv["id"] not in [i["id"] for i in client.get(API + "/investigations", headers=a2).json()["items"]]
    assert client.post(API + f"/investigations/{inv['id']}/reports", headers=a2, json={}).status_code == 404
    # owner, admin and assignees can
    assert client.get(API + f"/investigations/{inv['id']}", headers=a1).status_code == 200
    assert client.get(API + f"/investigations/{inv['id']}", headers=admin).status_code == 200
    a2_id = next(u["id"] for u in client.get(API + "/users", headers=admin).json() if u["username"] == "analyste2")
    client.patch(API + f"/investigations/{inv['id']}", headers=a1, json={"assignees": [a2_id]})
    assert client.get(API + f"/investigations/{inv['id']}", headers=a2).status_code == 200


def test_login_lockout_and_rate_limit(client, admin):
    for _ in range(5):
        assert client.post(API + "/auth/login", json={"username": "admin", "password": "wrong-password"}).status_code == 401
    assert client.post(API + "/auth/login", json={"username": "admin", "password": ADMIN[1]}).status_code == 423
    codes = [client.post(API + "/auth/login", json={"username": "nobody", "password": "x"}).status_code for _ in range(10)]
    assert 429 in codes


def test_logout_revokes_tokens(client, admin):
    assert client.post(API + "/auth/logout", headers=admin).status_code == 200
    assert client.get(API + "/auth/me", headers=admin).status_code == 401


def test_sql_injection_inputs_are_inert(client, admin):
    client.post(API + "/ingest/demo", headers=admin)
    for payload in ("' OR 1=1 --", "1; DROP TABLE investigations; --", "%' UNION SELECT password_hash FROM users --"):
        r = client.get(API + "/investigations", headers=admin, params={"q": payload, "ip": payload[:60], "source_system": payload[:60]})
        assert r.status_code == 200 and r.json()["total"] == 0
    assert client.get(API + "/investigations", headers=admin).json()["total"] > 0
    r = client.get(API + "/investigations", headers=admin, params={"indicator_type": "ipv4' OR '1'='1"})
    assert r.status_code == 422


def test_secrets_never_exposed_or_stored_in_clear(client, admin, env):
    secret = "SUPER-SECRET-API-KEY-123456"
    r = client.post(API + "/connectors", headers=admin, json={
        "kind": "siem", "provider": "generic_rest", "name": "rest1", "settings": {"url": "https://api.example.org/events"},
        "secrets": {"token": secret}})
    assert r.status_code == 201 and secret not in r.text
    assert secret not in client.get(API + "/connectors", headers=admin).text
    assert secret not in client.get(API + "/audit", headers=admin).text
    conn = sqlite3.connect(env / "makkadi.db")
    dump = "\n".join(conn.iterdump())
    conn.close()
    assert secret not in dump
    # masked value round-trip keeps the secret
    cid = r.json()["id"]
    client.patch(API + f"/connectors/{cid}", headers=admin, json={"secrets": {"token": "••••••••"}})
    from app.database.session import SessionLocal
    from app.security.secrets_vault import decrypt_secrets

    with SessionLocal() as db:
        assert decrypt_secrets(db.get(ConnectorConfig, cid).secret_ciphertext)["token"] == secret


def test_connector_url_ssrf_rejected(client, admin):
    r = client.post(API + "/connectors", headers=admin, json={
        "kind": "siem", "provider": "elastic", "name": "es-internal", "settings": {"base_url": "https://169.254.169.254"}})
    assert r.status_code == 422
    ok = client.post(API + "/connectors", headers=admin, json={
        "kind": "ai", "provider": "openai_compatible", "name": "local-llm", "settings": {"base_url": "http://127.0.0.1:11434/v1"}})
    assert ok.status_code == 201  # local model endpoint allowed for AI only


def test_validation_errors_do_not_echo_secrets(client, admin):
    r = client.post(API + "/connectors", headers=admin, json={"kind": "bad", "provider": "x", "name": "n",
                                                              "secrets": {"api_key": "LEAKME-999"}})
    assert r.status_code == 422 and "LEAKME-999" not in r.text


def _sign(secret, body, ts=None):
    ts = str(int(ts or time.time()))
    return {"X-Makkadi-Timestamp": ts, "X-Makkadi-Signature": compute_signature(secret, ts, body), "Content-Type": "application/json"}


def test_webhook_hmac(client, admin):
    client.post(API + "/connectors", headers=admin, json={
        "kind": "siem", "provider": "generic_rest", "name": "hook", "enabled": True,
        "settings": {"url": "https://api.example.org/x", "source_system": "wh"}, "secrets": {"webhook_secret": "s3cr3t"}})
    body = b'{"events":[{"id":"W1","src_ip":"154.73.112.25","severity":"high","title":"Webhook alert"}]}'
    assert client.post(API + "/ingest/webhook/hook", content=body, headers=_sign("wrong", body)).status_code == 401
    assert client.post(API + "/ingest/webhook/hook", content=body, headers=_sign("s3cr3t", body, time.time() - 3600)).status_code == 401
    assert client.post(API + "/ingest/webhook/nope", content=body, headers=_sign("s3cr3t", body)).status_code == 401
    ok = client.post(API + "/ingest/webhook/hook", content=body, headers=_sign("s3cr3t", body))
    assert ok.status_code == 200 and ok.json()["created"] == 1
    again = client.post(API + "/ingest/webhook/hook", content=body, headers=_sign("s3cr3t", body))
    assert again.json()["duplicates"] == 1


def test_security_headers(client):
    r = client.get(API + "/health")
    assert r.headers["x-frame-options"] == "DENY" and "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"


def test_bind_address_guard(monkeypatch):
    from app.core.config import Settings

    with pytest.raises(RuntimeError):
        Settings(host="0.0.0.0").check_bind_address()
    Settings(host="127.0.0.1").check_bind_address()
    Settings(host="0.0.0.0", allow_remote_bind=True).check_bind_address()


def test_audit_chain_detects_tampering(client, admin, db):
    from app.services.audit import verify_chain

    client.post(API + "/ingest/demo", headers=admin)
    assert verify_chain(db)["valid"]
    entry = db.scalars(select(AuditLog).order_by(AuditLog.id).offset(2).limit(1)).first()
    entry.details = {"forged": True}
    db.commit()
    result = verify_chain(db)
    assert result["valid"] is False and result["first_invalid_id"] == entry.id


def test_active_checks_disabled_by_default(client, admin):
    r = client.post(API + "/active-checks/tcp", headers=admin, json={"address": "8.8.8.8", "ports": [443], "justification": "test de refus"})
    assert r.status_code == 403


def test_active_checks_scope(monkeypatch, env):
    import asyncio

    from app.core.config import get_settings
    from app.core.errors import ValidationFailed
    from app.services.active_checks import authorize_target

    monkeypatch.setenv("MAKKADI_ACTIVE_CHECKS_ENABLED", "true")
    monkeypatch.setenv("MAKKADI_ACTIVE_CHECKS_ALLOWED_CIDRS", '["127.0.0.0/8"]')
    get_settings.cache_clear()
    with pytest.raises(ValidationFailed):
        authorize_target("8.8.8.8", [443])  # outside authorised scope
    with pytest.raises(ValidationFailed):
        authorize_target("127.0.0.0/24", [443])  # ranges refused
    with pytest.raises(ValidationFailed):
        authorize_target("127.0.0.1", [6379])  # port not allowed
    assert authorize_target("127.0.0.1", [22])
    asyncio.run(asyncio.sleep(0))


def test_env_file_in_data_dir_is_loaded(env):
    from app.core.config import get_settings

    (env / ".env").write_text("MAKKADI_APP_NAME=Marque-Test\n")
    get_settings.cache_clear()
    assert get_settings().app_name == "Marque-Test"
