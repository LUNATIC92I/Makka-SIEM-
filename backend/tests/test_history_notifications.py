import json

import httpx

from app.security.webhook import compute_signature
from tests.conftest import drain

API = "/api/v1"
IP = "154.73.112.25"


def _main_inv(client, h):
    return client.get(API + "/investigations", headers=h, params={"ip": IP}).json()["items"][0]


def test_rerun_keeps_enrichment_history(client, admin):
    client.post(API + "/ingest/demo", headers=admin)
    drain()
    inv = _main_inv(client, admin)
    first = client.get(API + f"/investigations/{inv['id']}", headers=admin).json()
    assert first["enrichment_runs"] == 1 and first["superseded_results"] == 0
    assert client.post(API + f"/investigations/{inv['id']}/run-now", headers=admin).status_code == 200
    second = client.get(API + f"/investigations/{inv['id']}", headers=admin).json()
    assert second["enrichment_runs"] == 2
    assert len(second["results"]) == len(first["results"])  # current view = latest run only
    assert second["superseded_results"] == len(first["results"])  # earlier run kept
    assert all(r["run_number"] == 2 and r["superseded_at"] is None for r in second["results"])
    ind = next(i for i in second["indicators"] if i["value"] == IP)
    history = client.get(API + f"/indicators/{ind['id']}", headers=admin).json()["history"]
    assert {r["run_number"] for r in history} == {1, 2}
    timeline = [t["label"] for t in second["timeline"] if t["kind"] == "osint_query"]
    assert any("remplacée" in label for label in timeline)


def _channel(client, h, provider="webhook", include_synthetic="true", url="https://hooks.example.org/makkadi"):
    r = client.post(API + "/connectors", headers=h, json={
        "kind": "notification", "provider": provider, "name": f"notif-{provider}", "enabled": True,
        "settings": {"min_risk_level": "élevé", "include_synthetic": include_synthetic},
        "secrets": {"url": url, "webhook_secret": "notif-secret"}})
    assert r.status_code == 201, r.text
    return r.json()


def test_webhook_notification_sent_once_and_signed(client, admin, mock_http):
    sent = []

    def handler(req):
        sent.append(req)
        return httpx.Response(204)

    mock_http(handler)
    ch = _channel(client, admin)
    assert "notif-secret" not in json.dumps(ch) and ch["secrets"]["url"] == "••••••••"
    client.post(API + "/ingest/demo", headers=admin)
    drain()
    high = [i for i in client.get(API + "/investigations", headers=admin).json()["items"] if i["risk_level"] in ("élevé", "critique")]
    assert high and len(sent) == len(high)
    req = sent[0]
    assert req.url.host == "hooks.example.org"
    ts, sig = req.headers["x-makkadi-timestamp"], req.headers["x-makkadi-signature"]
    assert sig == compute_signature("notif-secret", ts, req.content)
    body = json.loads(req.content)
    assert body["type"] == "investigation.risk_threshold" and body["synthetic_data"] is True
    assert "raw" not in body and "findings" not in json.dumps(body)
    # re-running at the same level does not notify again
    client.post(API + f"/investigations/{high[0]['id']}/run-now", headers=admin)
    drain()
    assert len(sent) == len(high)
    actions = [a["action"] for a in client.get(API + "/audit", headers=admin).json()]
    assert "notification.sent" in actions


def test_demo_data_not_notified_by_default_and_teams_format(client, admin, mock_http):
    sent = []
    mock_http(lambda req: (sent.append(req), httpx.Response(200))[1])
    _channel(client, admin, provider="teams", include_synthetic="false")
    client.post(API + "/ingest/demo", headers=admin)
    drain()
    assert sent == []
    from app.services.notifications import build_payload

    class Inv:
        reference, title, risk_level, risk_score, confidence_level, confidence_score = "INV-1", "t", "élevé", 70, "moyenne", 50
        severity, is_synthetic, created_at, events = "high", False, None, []

    assert set(build_payload("teams", Inv())) == {"text"}


def test_notification_url_ssrf_and_threshold_validation(client, admin):
    for url in ("http://hooks.example.org/x", "https://127.0.0.1/hook", "https://169.254.169.254/"):
        r = client.post(API + "/connectors", headers=admin, json={
            "kind": "notification", "provider": "webhook", "name": "bad", "settings": {}, "secrets": {"url": url}})
        assert r.status_code == 422, url
    r = client.post(API + "/connectors", headers=admin, json={
        "kind": "notification", "provider": "slack", "name": "bad2", "settings": {"min_risk_level": "énorme"}})
    assert r.status_code == 422


def test_failed_notification_is_retried_and_visible(client, admin, mock_http, db):
    from sqlalchemy import select

    from app.models import Task

    mock_http(lambda req: httpx.Response(503))
    _channel(client, admin)
    client.post(API + "/ingest/demo", headers=admin)
    drain()
    tasks = list(db.scalars(select(Task).where(Task.type == "notify")))
    assert tasks and all(t.status == "pending" and t.attempts == 1 and "503" in t.last_error for t in tasks)
    conn = next(c for c in client.get(API + "/connectors", headers=admin).json() if c["kind"] == "notification")
    assert conn["state"] == "en erreur"
