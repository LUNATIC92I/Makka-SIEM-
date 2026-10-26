"""URLhaus (abuse.ch), malware distribution URLs/hosts. Auth-Key required."""

from __future__ import annotations

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Findings, OsintProvider, ProviderResult, RelatedIndicator, Reputation
from app.core.timeutil import parse_timestamp


class UrlhausProvider(OsintProvider):
    name = "urlhaus"
    display_name = "URLhaus (abuse.ch)"
    category = "reputation"
    supported_types = {"ipv4", "domain", "url", "md5", "sha256"}
    requires_api_key = True
    secret_fields = ["api_key"]
    upstream_group = "abusech"
    reliability = 0.8
    terms_url = "https://urlhaus.abuse.ch/api/"
    description = "Hôtes/URL de distribution de logiciels malveillants. Périmètre : IPv4, domaines, URL, empreintes."
    BASE = "https://urlhaus-api.abuse.ch/v1"

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        if ind_type in ("ipv4", "domain"):
            endpoint, form = "host/", {"host": value}
        elif ind_type == "url":
            endpoint, form = "url/", {"url": value}
        else:
            endpoint, form = "payload/", {f"{ind_type}_hash": value}
        data, _ = await SafeHttpClient().post_json(
            f"{self.BASE}/{endpoint}", data=form, headers={"Auth-Key": self.ctx.secrets["api_key"]}
        )
        status = (data or {}).get("query_status")
        if status in ("no_results", "invalid_host", None):
            return self._result(ind_type, value, "no_data", raw=data,
                                error_message="Absent d'URLhaus (n'implique pas l'innocuité)")
        if status != "ok":
            return self._result(ind_type, value, "error", raw=data, error_message=f"URLhaus: {status}")
        urls = data.get("urls") or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        latest = max((parse_timestamp(u.get("date_added")) for u in urls), default=None,
                     key=lambda d: d.timestamp() if d else 0)
        findings = Findings(
            reputation=Reputation(
                verdict="malicious", score=90.0 if online else 70.0,
                raw_score=f"{len(urls)} URL(s), {online} en ligne", report_count=len(urls),
                last_reported_at=latest or parse_timestamp(data.get("firstseen")),
                categories=sorted({str(u.get("threat")) for u in urls if u.get("threat")}),
                explanation="Référencé par URLhaus comme distribuant des logiciels malveillants.",
            ),
            related=[RelatedIndicator(type="url", value=u["url"], relation="malware_url_hosted",
                                      first_seen=parse_timestamp(u.get("date_added"))) for u in urls[:20] if u.get("url")],
            tags=sorted({str(t) for u in urls for t in (u.get("tags") or [])})[:30],
        )
        return self._result(ind_type, value, "ok", findings=findings, raw=data,
                            reference_url=data.get("urlhaus_reference"), data_updated_at=latest,
                            source_confidence="curaté par abuse.ch")
