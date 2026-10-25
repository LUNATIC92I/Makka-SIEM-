"""ipinfo.io geolocation (token optional, free tier limits apply)."""

from __future__ import annotations

import re

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Findings, GeoInfo, NetworkInfo, OsintProvider, ProviderResult


class IpInfoProvider(OsintProvider):
    name = "ipinfo"
    display_name = "ipinfo.io (géolocalisation)"
    category = "geolocation"
    supported_types = {"ipv4", "ipv6"}
    upstream_group = "geo-ipinfo"
    reliability = 0.6
    terms_url = "https://ipinfo.io/terms-of-service"
    description = "Géolocalisation estimée et ASN. Jeton optionnel (quota gratuit limité)."
    secret_fields = ["token"]

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        token = self.ctx.secrets.get("token")
        params = {"token": token} if token else {}
        url = f"https://ipinfo.io/{value}/json"
        data, _ = await SafeHttpClient().get_json(url, params=params)
        if not data or data.get("bogon"):
            return self._result(ind_type, value, "no_data", raw=data, error_message="Aucune donnée de géolocalisation")
        lat = lon = None
        if isinstance(data.get("loc"), str) and "," in data["loc"]:
            lat, lon = (float(x) for x in data["loc"].split(",", 1))
        asn = name = None
        m = re.match(r"AS(\d+)\s*(.*)", data.get("org") or "")
        if m:
            asn, name = int(m.group(1)), m.group(2) or None
        findings = Findings(
            geo=GeoInfo(
                country_code=data.get("country"), country=data.get("country"), region=data.get("region"),
                city=data.get("city"), latitude=lat, longitude=lon,
                precision_note="Position estimée au niveau ville au mieux ; ne désigne pas l'emplacement d'une personne.",
            ),
            network=NetworkInfo(asn=asn, as_name=name),
        )
        if data.get("anycast"):
            findings.notes.append("Adresse anycast : la géolocalisation n'a pas de sens physique unique.")
        return self._result(ind_type, value, "ok", findings=findings, raw=data,
                            reference_url=f"https://ipinfo.io/{value}", source_confidence="estimation commerciale")
