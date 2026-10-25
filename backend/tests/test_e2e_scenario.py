"""End-to-end tests of the operational scenario (section 8 of the specification)."""

import json

import httpx
import pytest

from app.core.config import get_settings
from tests.conftest import drain

API = "/api/v1"
IP = "154.73.112.25"


def test_scenario_demo_mode(client, admin):
    # Step 1 - ingestion without manual input (demo SIEM feed)
    stats = client.post(API + "/ingest/demo", headers=admin).json()
    assert stats["created"] == 6 and stats["skipped_below_threshold"] == 1
    assert client.post(API + "/ingest/demo", headers=admin).json()["duplicates"] == 6  # no duplicates
    assert drain() >= 4

    inv = client.get(API + "/investigations", headers=admin, params={"ip": IP}).json()["items"][0]
    detail = client.get(API + f"/investigations/{inv['id']}", headers=admin).json()
    # Step 2 - extraction
    ev = detail["events"][0]
    assert ev["original_id"] == "DEMO-2026-0001" and ev["event_time"].endswith("22:14:35Z")
    assert (ev["src_ip"], ev["dst_ip"], ev["dst_port"], ev["protocol"], ev["hostname"], ev["severity"]) == (
        IP, "10.20.30.40", 22, "tcp", "srv-web-01", "high")
    roles = {(i["value"], i["role"], i["scope"]) for i in detail["indicators"]}
    assert (IP, "source", "public") in roles and ("10.20.30.40", "destination", "private") in roles
    assert len(detail["events"]) == 2  # second burst grouped into the same investigation
    # Step 3 - OSINT: only synthetic sources in demo mode, all labelled, with timestamps
    assert detail["results"] and all(r["is_synthetic"] and r["queried_at"] for r in detail["results"])
    assert not any(r["indicator"] == "10.20.30.40" for r in detail["results"])  # private IP never sent out
    # Step 4 - correlation: contradiction between the two demo geolocation sources, dependence handled
    corr = detail["correlation"]
    assert any(c["dimension"] == "pays estimé" for c in corr["contradictions"])
    rep = next(f for f in detail["scoring"]["risk_factors"] if f["key"] == "reputation")
    assert "même amont" in rep["rationale"]
    # Step 5 - AI analysis, structured and grounded
    analysis = detail["analysis"]
    assert analysis["status"] == "ok" and analysis["provider"] == "deterministic"
    out = analysis["output"]
    assert out["established_facts"] and out["alternative_hypotheses"] and out["limitations"]
    assert out["threat_actor_attribution"] == []
    assert any(m["technique_id"] == "T1110" for m in out["mitre_attack"])
    assert "DÉMONSTRATION" in out["executive_summary"]
    # Step 6 - presentation
    dash = client.get(API + "/dashboard", headers=admin).json()
    assert dash["counts"]["investigations"] >= 4 and dash["priority_investigations"]
    assert client.get(API + "/map", headers=admin).json()["warning"].startswith("Emplacements ESTIMÉS")
    graph = client.get(API + f"/investigations/{inv['id']}/graph", headers=admin).json()
    assert any(n["kind"] == "event" for n in graph["nodes"]) and graph["edges"]
    assert [t for t in detail["timeline"] if t["kind"] == "siem_event"]
    # Step 7 - reports
    for fmt in ("pdf", "json"):
        assert client.post(API + f"/investigations/{inv['id']}/reports", headers=admin, json={"format": fmt}).status_code == 201
    # Traceability
    assert client.get(API + "/audit/verify", headers=admin).json()["valid"]
    actions = {a["action"] for a in client.get(API + "/audit", headers=admin, params={"target_id": inv["id"]}).json()}
    assert {"investigation.created", "investigation.enriched", "ai.analysis", "report.generated"} <= actions
    # Injection attempt in a log field was detected and flagged
    inj = client.get(API + "/investigations", headers=admin, params={"q": "IGNORE"}).json()["items"][0]
    flags = client.get(API + f"/investigations/{inj['id']}", headers=admin).json()["analysis"]["injection_flags"]
    assert {f["pattern"] for f in flags} >= {"ignore_instructions"}


@pytest.fixture
def real_mode(monkeypatch, env):
    monkeypatch.setenv("MAKKADI_DEMO_MODE", "false")
    get_settings.cache_clear()


def test_scenario_with_real_connectors_mocked(real_mode, client, admin, mock_http, tmp_path):
    """Same scenario, demo mode OFF: automatic SIEM collection + real OSINT connectors (HTTP mocked)."""
    inbox = tmp_path / "inbox"
    inbox.mkdir()
    (inbox / "alert.json").write_text(json.dumps([{
        "id": "SIEM-778899", "timestamp": "2026-10-25T22:14:35Z", "title": "Connexions suspectes répétées",
        "severity": "high", "src_ip": IP, "dst_ip": "10.20.30.40", "dst_port": 22, "protocol": "tcp",
        "hostname": "srv-web-01", "attempt_count": 48}]))

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "rdap.org":
            return httpx.Response(200, json={"name": "TEST-NET-BLOCK", "port43": "whois.afrinic.net", "country": "ZZ",
                                             "entities": [{"roles": ["registrant"], "vcardArray": ["vcard", [["kind", {}, "text", "org"], ["fn", {}, "text", "Registrant Org (mock)"]]]}],
                                             "links": [{"rel": "self", "href": f"https://rdap.afrinic.net/rdap/ip/{IP}"}]})
        if req.url.host == "stat.ripe.net":
            return httpx.Response(200, json={"data": {"announced": True, "resource": "154.73.112.0/22", "asns": [{"asn": 64501, "holder": "MOCK-AS"}]}})
        if req.url.host == "api.abuseipdb.com":
            return httpx.Response(200, json={"data": {"abuseConfidenceScore": 100, "totalReports": 250, "numDistinctUsers": 80,
                                                      "lastReportedAt": "2026-10-25T20:00:00+00:00"}})
        return httpx.Response(404)

    mock_http(handler)
    conns = {c["name"]: c for c in client.get(API + "/connectors", headers=admin).json()}
    for name in ("rdap", "ripestat"):
        client.patch(API + f"/connectors/{conns[name]['id']}", headers=admin, json={"enabled": True})
    client.patch(API + f"/connectors/{conns['abuseipdb']['id']}", headers=admin, json={"enabled": True, "secrets": {"api_key": "k"}})
    client.patch(API + f"/connectors/{conns['virustotal']['id']}", headers=admin, json={"enabled": True})  # enabled but no key
    vt = next(c for c in client.get(API + "/connectors", headers=admin).json() if c["name"] == "virustotal")
    assert vt["state"] == "non configuré"
    siem = client.post(API + "/connectors", headers=admin, json={"kind": "siem", "provider": "json_folder", "name": "inbox",
                                                                 "enabled": True, "settings": {"directory": str(inbox), "source_system": "siem-test"}}).json()
    from app.database.session import SessionLocal
    from app.investigation.pipeline import schedule_due_polls

    with SessionLocal() as db:
        assert schedule_due_polls(db) == 1
    drain()
    inv = client.get(API + "/investigations", headers=admin, params={"ip": IP}).json()["items"][0]
    detail = client.get(API + f"/investigations/{inv['id']}", headers=admin).json()
    assert detail["events"][0]["original_id"] == "SIEM-778899" and not detail["is_synthetic"]
    by_source = {r["source"]: r for r in detail["results"]}
    assert set(by_source) == {"rdap", "ripestat", "abuseipdb", "virustotal"}
    assert not any(r["is_synthetic"] for r in detail["results"])
    assert by_source["virustotal"]["status"] == "not_configured" and by_source["virustotal"]["error_message"]
    assert by_source["rdap"]["findings"]["network"]["registered_org"] == "Registrant Org (mock)"
    assert by_source["abuseipdb"]["reference_url"] == f"https://www.abuseipdb.com/check/{IP}"
    assert any("géolocalisation" in m for m in detail["correlation"]["missing"])  # no geo source configured
    assert detail["pipeline_status"] == "partial"  # collection error surfaced
    assert detail["risk_level"] in ("élevé", "critique") and detail["confidence_level"]
    siem_row = next(c for c in client.get(API + "/connectors", headers=admin).json() if c["name"] == "inbox")
    assert siem_row["last_status"] == "ok" and siem_row["id"] == siem["id"]
