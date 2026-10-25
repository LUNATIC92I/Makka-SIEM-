import json

from tests.conftest import drain

API = "/api/v1"


def _inv(client, h):
    client.post(API + "/ingest/demo", headers=h)
    drain()
    items = client.get(API + "/investigations", headers=h, params={"ip": "154.73.112.25"}).json()["items"]
    return items[0]


def test_pdf_and_json_reports(client, admin):
    inv = _inv(client, admin)
    for kind in ("technical", "executive"):
        pdf = client.post(API + f"/investigations/{inv['id']}/reports", headers=admin, json={"kind": kind, "format": "pdf"}).json()
        body = client.get(API + f"/reports/{pdf['id']}/download", headers=admin)
        assert body.status_code == 200 and body.content.startswith(b"%PDF") and len(body.content) > 5000
        assert body.headers["x-content-sha256"] == pdf["sha256"]
    js = client.post(API + f"/investigations/{inv['id']}/reports", headers=admin, json={"kind": "technical", "format": "json"}).json()
    data = json.loads(client.get(API + f"/reports/{js['id']}/download", headers=admin).content)
    for key in ("schema_version", "investigation", "alert_context", "indicators", "osint_results", "timeline", "relations",
                "risk_assessment", "ai_analysis", "limitations", "generated_at"):
        assert key in data
    assert data["contains_synthetic_data"] is True
    assert data["osint_results"]["provenance"] == "third_party" and data["ai_analysis"]["provenance"] == "ai_generated"
    assert data["alert_context"]["events"][0]["original_id"] == "DEMO-2026-0001"
    assert all(i["queried_at"] for i in data["osint_results"]["items"])


def test_report_tamper_detection(client, admin, env):
    inv = _inv(client, admin)
    rep = client.post(API + f"/investigations/{inv['id']}/reports", headers=admin, json={"format": "json"}).json()
    assert client.get(API + f"/reports/{rep['id']}/verify", headers=admin).json()["valid"] is True
    path = env / "reports" / rep["file_name"]
    path.write_bytes(path.read_bytes().replace(b"DEMO-2026-0001", b"DEMO-2026-9999"))
    assert client.get(API + f"/reports/{rep['id']}/verify", headers=admin).json()["valid"] is False


def test_pdf_escapes_untrusted_markup():
    from app.reporting.pdf_report import _t

    assert "<" not in _t('<font color="red">x</font><img src="file:///etc/passwd"/>')


def test_render_pdf_with_hostile_content(client, admin):
    body = {"events": [{"id": "X1", "src_ip": "8.8.8.8", "severity": "high",
                        "title": '<para><img src="/etc/passwd"/></para> & <b>gras</b> ≠ → 测试'}]}
    files = {"file": ("e.json", json.dumps(body), "application/json")}
    client.post(API + "/ingest/file", headers=admin, files=files)
    drain()
    inv = client.get(API + "/investigations", headers=admin, params={"ip": "8.8.8.8"}).json()["items"][0]
    r = client.post(API + f"/investigations/{inv['id']}/reports", headers=admin, json={"format": "pdf"})
    assert r.status_code == 201
