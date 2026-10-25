import asyncio
import json
from urllib.parse import parse_qs

import httpx
import pytest

from app.connectors.siem.base import ConnectorContext, normalize_severity, normalize_with_mapping
from app.connectors.siem.connectors import (
    DefenderConnector, ElasticConnector, GenericRestConnector, JsonFolderConnector, SentinelConnector,
    SplunkConnector, WazuhConnector, parse_event_document,
)
from app.core.errors import AuthExpired, ConnectorError, RateLimited


def run(coro):
    return asyncio.run(coro)


@pytest.mark.parametrize("raw,expected", [
    ("High", "high"), ("informational", "info"), ("critical", "critical"), (12, "critical"), (5, "medium"),
    (2, "low"), (0, "info"), (99, "critical"), (50, "high"), ("", "unknown"), ("bizarre", "unknown"), ("10", "high"),
])
def test_severity_normalization(raw, expected):
    assert normalize_severity(raw) == expected


def test_normalize_default_mapping_and_flattened_keys():
    raw = {"id": "A1", "@timestamp": "2026-10-25T22:14:35.123456789Z", "rule.name": "SSH brute force",
           "source.ip": "154.73.112.25", "destination": {"ip": "10.0.0.5", "port": 22}, "host": {"name": "srv-1"},
           "severity": "high", "count": "48"}
    ev = normalize_with_mapping(raw, "test")
    assert ev.original_id == "A1" and ev.src_ip == "154.73.112.25" and ev.dst_ip == "10.0.0.5"
    assert ev.dst_port == 22 and ev.hostname == "srv-1" and ev.attempt_count == 48
    assert ev.event_time.isoformat().startswith("2026-10-25T22:14:35.123456")


def test_event_without_id_gets_deterministic_id():
    a = normalize_with_mapping({"src_ip": "1.1.1.1", "title": "x"}, "s")
    b = normalize_with_mapping({"title": "x", "src_ip": "1.1.1.1"}, "s")
    assert a.original_id == b.original_id and a.original_id.startswith("sha256:")


def test_parse_event_document_rejects_garbage():
    with pytest.raises(ConnectorError):
        parse_event_document("nope", "s")
    assert len(parse_event_document({"events": [{"id": 1}, "bad", {"id": 2}]}, "s")) == 2


def test_json_folder_resume(tmp_path):
    (tmp_path / "a.json").write_text(json.dumps([{"id": "1", "src_ip": "8.8.8.8"}]))
    conn = JsonFolderConnector(ConnectorContext("f", {"directory": str(tmp_path)}, {}))
    first = run(conn.fetch(None))
    assert len(first.events) == 1
    again = run(conn.fetch(first.next_cursor))
    assert again.events == []  # already processed
    (tmp_path / "b.json").write_text(json.dumps({"events": [{"id": "2"}]}))
    (tmp_path / "broken.json").write_text("{not json")
    third = run(conn.fetch(again.next_cursor))
    assert [e.original_id for e in third.events] == ["2"] and third.warnings


def _token_response():
    return httpx.Response(200, json={"access_token": "tok-1", "expires_in": 3600})


def test_sentinel_query_and_token_refresh(env, mock_http):
    calls = {"token": 0, "query": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if "login.microsoftonline.com" in req.url.host:
            calls["token"] += 1
            return _token_response()
        calls["query"] += 1
        if calls["query"] == 1:
            return httpx.Response(401)  # expired token -> refresh once
        body = json.loads(req.content)
        assert "SecurityAlert | where TimeGenerated >= datetime(" in body["query"]
        return httpx.Response(200, json={"tables": [{"columns": [{"name": n} for n in (
            "SystemAlertId", "TimeGenerated", "AlertName", "AlertSeverity", "Entities", "CompromisedEntity")],
            "rows": [["sa-1", "2026-10-25T22:14:35Z", "Brute force", "High",
                      json.dumps([{"Type": "ip", "Address": "154.73.112.25"}]), "srv-web-01"]]}]})

    mock_http(handler)
    conn = SentinelConnector(ConnectorContext("s", {"tenant_id": "t", "client_id": "c", "workspace_id": "w"},
                                              {"client_secret": "x"}))
    res = run(conn.fetch("2026-10-25T00:00:00Z"))
    ev = res.events[0]
    assert ev.original_id == "sa-1" and ev.src_ip == "154.73.112.25" and ev.severity == "high"
    assert ev.hostname == "srv-web-01" and res.next_cursor == "2026-10-25T22:14:35Z"
    assert calls["token"] == 2


def test_sentinel_rejects_kql_injection():
    conn = SentinelConnector(ConnectorContext("s", {"kql_filter": "true | union SigninLogs"}, {}))
    with pytest.raises(ConnectorError):
        conn.build_query("2026-01-01T00:00:00Z", 10)


def test_splunk_export_parsing(env, mock_http):
    def handler(req):
        form = parse_qs(req.content.decode())
        assert form["output_mode"] == ["json"] and "earliest=" in form["search"][0]
        assert req.headers["authorization"] == "Bearer splunk-token"
        lines = [json.dumps({"result": {"event_id": "n1", "_time": "2026-10-25T22:14:35.000+00:00", "rule_name": "Excessive Failed Logins",
                                        "urgency": "high", "src": "154.73.112.25", "dest": "srv-web-01", "count": "48"}}),
                 json.dumps({"preview": False, "lastrow": True})]
        return httpx.Response(200, text="\n".join(lines))

    mock_http(handler)
    conn = SplunkConnector(ConnectorContext("sp", {"base_url": "https://splunk.example.org:8089"}, {"token": "splunk-token"}))
    ev = run(conn.fetch("2026-10-25T00:00:00Z")).events[0]
    assert (ev.original_id, ev.src_ip, ev.severity, ev.attempt_count) == ("n1", "154.73.112.25", "high", 48)


def test_elastic_and_wazuh(env, mock_http):
    def handler(req):
        body = json.loads(req.content)
        if "wazuh-alerts" in req.url.path:
            assert "timestamp" in body["query"]["range"]
            return httpx.Response(200, json={"hits": {"hits": [{"_id": "w1", "_source": {
                "id": "1729894475.123", "timestamp": "2026-10-25T22:14:35.000+0000", "rule": {"level": 10, "description": "sshd: brute force", "firedtimes": 12},
                "data": {"srcip": "154.73.112.25"}, "agent": {"name": "srv-web-01"}}}]}})
        assert req.headers["authorization"] == "ApiKey k"
        return httpx.Response(200, json={"hits": {"hits": [{"_id": "e1", "_source": {
            "@timestamp": "2026-10-25T22:14:35Z", "kibana.alert.uuid": "uuid-1", "kibana.alert.rule.name": "SSH brute",
            "kibana.alert.severity": "critical", "source": {"ip": "154.73.112.25"}, "host": {"name": "srv"}}}]}})

    mock_http(handler)
    el = run(ElasticConnector(ConnectorContext("e", {"base_url": "https://es.example.org"}, {"api_key": "k"})).fetch(None)).events[0]
    assert (el.original_id, el.severity, el.src_ip) == ("uuid-1", "critical", "154.73.112.25")
    wz = run(WazuhConnector(ConnectorContext("w", {"base_url": "https://wazuh.example.org"}, {"username": "u", "password": "p"})).fetch(None)).events[0]
    assert (wz.original_id, wz.severity, wz.src_ip, wz.hostname, wz.attempt_count) == ("1729894475.123", "high", "154.73.112.25", "srv-web-01", 12)


def test_defender_evidence(env, mock_http):
    def handler(req):
        if "login.microsoftonline.com" in req.url.host:
            return _token_response()
        assert req.url.path == "/v1.0/security/alerts_v2"
        return httpx.Response(200, json={"value": [{"id": "da1", "createdDateTime": "2026-10-25T22:14:35Z", "title": "Password spray",
                                                    "severity": "medium", "category": "CredentialAccess",
                                                    "evidence": [{"@odata.type": "#microsoft.graph.security.ipEvidence", "ipAddress": "154.73.112.25"},
                                                                 {"@odata.type": "#microsoft.graph.security.deviceEvidence", "deviceDnsName": "srv-web-01"}]}]})

    mock_http(handler)
    ev = run(DefenderConnector(ConnectorContext("d", {"tenant_id": "t", "client_id": "c"}, {"client_secret": "s"})).fetch(None)).events[0]
    assert (ev.original_id, ev.src_ip, ev.hostname, ev.severity) == ("da1", "154.73.112.25", "srv-web-01", "medium")


def test_generic_rest_errors(env, mock_http, monkeypatch):
    import app.connectors.http as http_mod

    async def no_sleep(_):
        return None

    monkeypatch.setattr(http_mod.asyncio, "sleep", no_sleep)
    state = {"n": 0}

    def handler(req):
        state["n"] += 1
        if req.url.path == "/rate":
            return httpx.Response(429, headers={"retry-after": "1"})
        if req.url.path == "/flaky" and state["n"] < 3:
            return httpx.Response(503)
        if req.url.path == "/auth":
            return httpx.Response(401)
        return httpx.Response(200, json={"data": {"items": [{"id": "g1", "timestamp": "2026-10-25T22:14:35Z", "src_ip": "8.8.8.8"}]}})

    mock_http(handler)
    mk = lambda path: GenericRestConnector(ConnectorContext("g", {"url": f"https://api.example.org{path}", "items_path": "data.items", "initial_lookback_minutes": 5256000}, {"token": "t"}))  # noqa: E731
    with pytest.raises(RateLimited):
        run(mk("/rate").fetch(None))
    with pytest.raises(AuthExpired):
        run(mk("/auth").fetch(None))
    state["n"] = 0
    res = run(mk("/flaky").fetch(None))  # two 503 then success (retry with backoff)
    assert res.events[0].original_id == "g1" and res.next_cursor == "2026-10-25T22:14:35Z"


def test_missing_parameter_is_explicit():
    with pytest.raises(ConnectorError, match="Paramètre manquant"):
        run(SplunkConnector(ConnectorContext("x", {}, {})).fetch(None))
