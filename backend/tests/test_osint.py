import asyncio

import httpx
import pytest

from app.connectors.osint.abuseipdb import AbuseIpDbProvider
from app.connectors.osint.base import ProviderContext
from app.connectors.osint.crtsh import CrtShProvider
from app.connectors.osint.demo import DEMO_PROVIDERS
from app.connectors.osint.greynoise import GreyNoiseProvider
from app.connectors.osint.internal_list import InternalListProvider
from app.connectors.osint.internetdb import InternetDbProvider
from app.connectors.osint.misp import MispProvider
from app.connectors.osint.otx import OtxProvider
from app.connectors.osint.rdap import RdapProvider
from app.connectors.osint.ripestat import RipeStatProvider
from app.connectors.osint.taxii import TaxiiProvider
from app.connectors.osint.urlhaus import UrlhausProvider
from app.connectors.osint.virustotal import VirusTotalProvider

IP = "154.73.112.25"


def lookup(cls, t="ipv4", v=IP, settings=None, secrets=None):
    return asyncio.run(cls(ProviderContext(settings or {}, secrets or {})).lookup(t, v))


def test_rdap_keeps_only_organisations(env, mock_http):
    def handler(req):
        if req.url.host == "rdap.org":
            return httpx.Response(302, headers={"location": f"https://rdap.afrinic.net/rdap/ip/{IP}"})
        return httpx.Response(200, json={
            "handle": "NET-1", "name": "EXAMPLE-NET", "country": "ZZ", "port43": "whois.afrinic.net",
            "cidr0_cidrs": [{"v4prefix": "154.73.112.0", "length": 22}],
            "entities": [
                {"roles": ["registrant"], "vcardArray": ["vcard", [["kind", {}, "text", "org"], ["fn", {}, "text", "Example Org Ltd"]]]},
                {"roles": ["registrant", "abuse"], "vcardArray": ["vcard", [["kind", {}, "text", "individual"], ["fn", {}, "text", "Jean Dupont"]]]},
            ],
            "events": [{"eventAction": "registration", "eventDate": "2018-01-01T00:00:00Z"},
                       {"eventAction": "last changed", "eventDate": "2024-05-01T00:00:00Z"}],
            "links": [{"rel": "self", "href": f"https://rdap.afrinic.net/rdap/ip/{IP}"}]})

    mock_http(handler)
    r = lookup(RdapProvider)
    assert r.status == "ok" and r.findings.network.registered_org == "Example Org Ltd"
    assert r.findings.network.cidr == "154.73.112.0/22" and r.findings.network.rir == "AFRINIC"
    assert "Jean Dupont" not in str(r.findings.model_dump())  # no personal data
    assert r.reference_url == f"https://rdap.afrinic.net/rdap/ip/{IP}" and r.raw_sha256 and r.queried_at


def test_gzip_responses_are_decoded(env, mock_http):
    import gzip
    import json as _json

    body = gzip.compress(_json.dumps({"ip": IP, "ports": [22], "hostnames": [], "tags": [], "vulns": [], "cpes": []}).encode())
    mock_http(lambda req: httpx.Response(200, content=body, headers={"content-encoding": "gzip", "content-type": "application/json"}))
    assert lookup(InternetDbProvider).findings.services.ports == [22]


def test_rdap_redirect_to_internal_is_blocked(env, mock_http):
    mock_http(lambda req: httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data/"}))
    r = lookup(RdapProvider)
    assert r.status == "error" and "refusée" in r.error_message


def test_ripestat(env, mock_http):
    mock_http(lambda req: httpx.Response(200, json={"query_time": "2026-10-25T22:00:00", "data": {
        "resource": "154.73.112.0/22", "announced": True, "asns": [{"asn": 64500, "holder": "EXAMPLE-AS"}], "block": {"name": "AFRINIC"}}}))
    r = lookup(RipeStatProvider)
    assert r.findings.network.asn == 64500 and r.findings.network.bgp_prefix == "154.73.112.0/22"
    mock_http(lambda req: httpx.Response(200, json={"data": {"announced": False, "asns": []}}))
    assert lookup(RipeStatProvider).status == "no_data"


def test_virustotal_verdicts_and_not_configured(env, mock_http):
    assert lookup(VirusTotalProvider).status == "not_configured"
    mock_http(lambda req: httpx.Response(200, json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 60, "undetected": 30}, "last_analysis_date": 1761430475}}}))
    r = lookup(VirusTotalProvider, secrets={"api_key": "k"})
    assert r.findings.reputation.verdict == "unknown"  # no detection != benign
    mock_http(lambda req: httpx.Response(200, json={"data": {"attributes": {
        "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 50, "undetected": 30}, "asn": 64500, "as_owner": "X"}}}))
    r = lookup(VirusTotalProvider, secrets={"api_key": "k"})
    assert r.findings.reputation.verdict == "malicious" and r.reference_url.endswith(IP)
    mock_http(lambda req: httpx.Response(404))
    assert lookup(VirusTotalProvider, secrets={"api_key": "k"}).status == "no_data"


def test_abuseipdb_and_rate_limit(env, mock_http, monkeypatch):
    import app.connectors.http as http_mod

    async def no_sleep(_):
        return None

    monkeypatch.setattr(http_mod.asyncio, "sleep", no_sleep)
    mock_http(lambda req: httpx.Response(200, json={"data": {"abuseConfidenceScore": 88, "totalReports": 120, "numDistinctUsers": 30,
                                                             "lastReportedAt": "2026-10-20T10:00:00+00:00", "isp": "Example ISP", "isTor": True}}))
    r = lookup(AbuseIpDbProvider, secrets={"api_key": "k"})
    assert r.findings.reputation.verdict == "malicious" and "tor-exit-node" in r.findings.tags
    mock_http(lambda req: httpx.Response(429, headers={"retry-after": "2"}))
    assert lookup(AbuseIpDbProvider, secrets={"api_key": "k"}).status == "rate_limited"
    mock_http(lambda req: httpx.Response(500))
    r = lookup(AbuseIpDbProvider, secrets={"api_key": "k"})
    assert r.status == "error" and "k" not in (r.error_message or "").split()


def test_otx_urlhaus_greynoise_internetdb(env, mock_http):
    mock_http(lambda req: httpx.Response(200, json={"pulse_info": {"count": 2, "pulses": [
        {"id": "p1", "name": "SSH brute forcers", "modified": "2026-10-01T00:00:00", "tags": ["ssh"]}, {"id": "p2", "name": "Scanners"}]}}))
    r = lookup(OtxProvider, secrets={"api_key": "k"})
    assert r.findings.reputation.verdict == "suspicious" and len(r.findings.campaigns) == 2
    mock_http(lambda req: httpx.Response(200, json={"query_status": "no_results"}))
    assert lookup(UrlhausProvider, secrets={"api_key": "k"}).status == "no_data"
    assert lookup(UrlhausProvider, t="ipv6", v="2606:4700::1", secrets={"api_key": "k"}).status == "unsupported"
    mock_http(lambda req: httpx.Response(200, json={"ip": IP, "noise": True, "riot": False, "classification": "malicious",
                                                    "last_seen": "2026-10-24", "link": "https://viz.greynoise.io/ip/x"}))
    assert lookup(GreyNoiseProvider).findings.reputation.verdict == "malicious"
    mock_http(lambda req: httpx.Response(404, json={"message": "IP not observed"}))
    assert lookup(GreyNoiseProvider).status == "no_data"
    mock_http(lambda req: httpx.Response(200, json={"ip": IP, "ports": [22, 443], "hostnames": [], "tags": [], "vulns": [], "cpes": []}))
    assert lookup(InternetDbProvider).findings.services.ports == [22, 443]


def test_crtsh_temporality(env, mock_http):
    mock_http(lambda req: httpx.Response(200, json=[
        {"id": 1, "issuer_name": "CA", "common_name": "a.example.org", "name_value": "a.example.org\nb.example.org",
         "not_before": "2020-01-01T00:00:00", "not_after": "2020-04-01T00:00:00", "entry_timestamp": "2020-01-01T00:00:00"},
        {"id": 2, "issuer_name": "CA", "common_name": "a.example.org", "name_value": "a.example.org\nc.example.org",
         "not_before": "2026-09-01T00:00:00", "not_after": "2099-01-01T00:00:00", "entry_timestamp": "2026-09-01T00:00:00"}]))
    r = lookup(CrtShProvider, t="domain", v="a.example.org")
    rel = {x.value: x.relation for x in r.findings.related}
    assert rel["b.example.org"].endswith("historical") and rel["c.example.org"].endswith("current")


def test_misp_and_taxii_and_internal(env, mock_http, tmp_path):
    mock_http(lambda req: httpx.Response(200, json={"response": {"Attribute": [
        {"value": IP, "to_ids": True, "timestamp": "1761430475", "Event": {"id": "42", "info": "Campagne X"}, "Tag": [{"name": "tlp:amber"}]}]}}))
    r = lookup(MispProvider, settings={"base_url": "https://misp.example.org"}, secrets={"api_key": "k"})
    assert r.findings.reputation.verdict == "malicious" and r.findings.campaigns[0].reference.endswith("/events/view/42")
    mock_http(lambda req: httpx.Response(200, json={"objects": [
        {"type": "indicator", "id": "indicator--1", "name": "Bad IP", "pattern": f"[ipv4-addr:value = '{IP}']", "modified": "2026-10-01T00:00:00Z"}]}))
    r = lookup(TaxiiProvider, settings={"api_root": "https://taxii.example.org/api", "collection_id": "c1"})
    assert r.status == "ok" and r.findings.reputation.report_count == 1
    f = tmp_path / "list.csv"
    f.write_text(f"type,value,verdict,comment\nipv4,{IP},malicious,Bloqué par le SOC\n")
    assert lookup(InternalListProvider, settings={"file_path": str(f)}).findings.reputation.verdict == "malicious"
    assert lookup(InternalListProvider, v="8.8.8.8", settings={"file_path": str(f)}).status == "no_data"


def test_provider_crash_is_contained(env, mock_http):
    mock_http(lambda req: httpx.Response(200, json={"data": {"attributes": "not-a-dict"}}))
    r = lookup(VirusTotalProvider, secrets={"api_key": "k"})
    assert r.status == "error" and "Erreur interne" in r.error_message


@pytest.mark.parametrize("cls", DEMO_PROVIDERS)
def test_demo_providers_are_flagged(cls):
    r = asyncio.run(cls(ProviderContext({}, {})).lookup("ipv4", IP))
    assert r.is_synthetic and "DÉMONSTRATION" in r.findings.notes[0]
    if r.findings.network and r.findings.network.asn:
        assert 64496 <= r.findings.network.asn <= 64511  # documentation ASN range
    if r.findings.geo:
        assert r.findings.geo.country_code in ("XA", "XB")
