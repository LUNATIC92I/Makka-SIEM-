"""RIPEstat Data API — BGP routing: announcing ASN, prefix and AS holder (all RIRs)."""

from __future__ import annotations

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Findings, NetworkInfo, OsintProvider, ProviderResult
from app.core.timeutil import parse_timestamp


class RipeStatProvider(OsintProvider):
    name = "ripestat"
    display_name = "RIPEstat (BGP / ASN)"
    category = "network"
    supported_types = {"ipv4", "ipv6"}
    upstream_group = "bgp-routing"
    reliability = 0.85
    terms_url = "https://stat.ripe.net/docs/data_api#terms-and-conditions"
    description = "Préfixe annoncé et ASN d'origine observés dans BGP (RIS). Sans clé."
    BASE = "https://stat.ripe.net/data"

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        url = f"{self.BASE}/prefix-overview/data.json"
        params = {"resource": value, "sourceapp": "makkadi"}
        data, _ = await SafeHttpClient().get_json(url, params=params)
        payload = (data or {}).get("data") or {}
        ref = f"https://stat.ripe.net/{value}"
        if not payload.get("announced") or not payload.get("asns"):
            return self._result(
                ind_type, value, "no_data", raw=data, reference_url=ref,
                error_message="Préfixe non annoncé dans BGP au moment de la requête",
            )
        first = payload["asns"][0]
        block = payload.get("block") or {}
        findings = Findings(
            network=NetworkInfo(
                asn=int(first.get("asn")) if first.get("asn") is not None else None,
                as_name=first.get("holder"),
                bgp_prefix=payload.get("resource"),
                network_name=block.get("name"),
            )
        )
        if len(payload["asns"]) > 1:
            findings.notes.append(
                "Préfixe annoncé par plusieurs ASN (MOAS) : " + ", ".join(str(a.get("asn")) for a in payload["asns"])
            )
        return self._result(
            ind_type, value, "ok", findings=findings, raw=data, reference_url=ref,
            data_updated_at=parse_timestamp((data or {}).get("query_time")),
            source_confidence="observation BGP (RIPE RIS)",
        )
