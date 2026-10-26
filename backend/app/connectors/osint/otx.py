"""AlienVault OTX, community threat intelligence pulses."""

from __future__ import annotations

from urllib.parse import quote

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Campaign, Findings, OsintProvider, ProviderResult, Reputation
from app.core.timeutil import parse_timestamp

_SECTIONS = {"ipv4": "IPv4", "ipv6": "IPv6", "domain": "domain", "url": "url", "md5": "file", "sha1": "file", "sha256": "file"}


class OtxProvider(OsintProvider):
    name = "otx"
    display_name = "AlienVault OTX"
    category = "threat_intel"
    supported_types = set(_SECTIONS)
    requires_api_key = True
    secret_fields = ["api_key"]
    upstream_group = "otx-community"
    reliability = 0.45
    terms_url = "https://otx.alienvault.com/terms"
    description = "Pulses communautaires (qualité variable, rediffusent souvent d'autres flux)."

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        section = _SECTIONS[ind_type]
        url = f"https://otx.alienvault.com/api/v1/indicators/{section}/{quote(value, safe='')}/general"
        data, _ = await SafeHttpClient().get_json(url, headers={"X-OTX-API-KEY": self.ctx.secrets["api_key"]})
        ref = f"https://otx.alienvault.com/indicator/{section.lower()}/{quote(value, safe='')}"
        if not data:
            return self._result(ind_type, value, "no_data", reference_url=ref)
        pulse_info = data.get("pulse_info") or {}
        pulses = pulse_info.get("pulses") or []
        count = int(pulse_info.get("count") or len(pulses))
        latest = max((parse_timestamp(p.get("modified") or p.get("created")) for p in pulses), default=None,
                     key=lambda d: d.timestamp() if d else 0)
        findings = Findings(
            reputation=Reputation(
                verdict="suspicious" if count else "unknown",
                score=min(100.0, count * 15.0) if count else None,
                raw_score=f"{count} pulse(s)", report_count=count, last_reported_at=latest,
                explanation="Présence dans des pulses communautaires : signal à corroborer." if count
                else "Absent des pulses OTX (n'implique pas l'innocuité).",
            ),
            campaigns=[
                Campaign(name=str(p.get("name"))[:200], reference=f"https://otx.alienvault.com/pulse/{p.get('id')}",
                         source_statement="Pulse OTX communautaire (non vérifié)")
                for p in pulses[:10] if p.get("name")
            ],
            tags=sorted({str(t) for p in pulses for t in (p.get("tags") or [])})[:30],
        )
        return self._result(ind_type, value, "ok", findings=findings, raw=data, reference_url=ref,
                            data_updated_at=latest, source_confidence="communautaire")
