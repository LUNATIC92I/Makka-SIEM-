"""Shodan InternetDB, passive view of exposed ports/services (no scan performed by MAKKADi)."""

from __future__ import annotations

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import ExposedServices, Findings, OsintProvider, ProviderResult, Resolution


class InternetDbProvider(OsintProvider):
    name = "internetdb"
    display_name = "Shodan InternetDB (passif)"
    category = "services"
    supported_types = {"ipv4"}
    upstream_group = "shodan-scans"
    reliability = 0.7
    terms_url = "https://internetdb.shodan.io/"
    description = "Ports, CPE et vulnérabilités observés par Shodan (données passives, sans clé, usage non commercial)."

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        data, resp = await SafeHttpClient().get_json(f"https://internetdb.shodan.io/{value}")
        ref = f"https://www.shodan.io/host/{value}"
        if resp.status_code == 404 or not data or not data.get("ports"):
            return self._result(ind_type, value, "no_data", raw=data, reference_url=ref,
                                error_message="Aucun service observé par Shodan")
        findings = Findings(
            services=ExposedServices(
                ports=sorted(int(p) for p in data.get("ports") or []), hostnames=data.get("hostnames") or [],
                tags=data.get("tags") or [], vulns=(data.get("vulns") or [])[:50], cpes=(data.get("cpes") or [])[:50],
            ),
            resolutions=[Resolution(type="PTR/hostname", value=h, temporality="unknown") for h in (data.get("hostnames") or [])[:20]],
            tags=data.get("tags") or [],
        )
        findings.notes.append("Données de scan Shodan à une date non précisée par InternetDB : à vérifier.")
        return self._result(ind_type, value, "ok", findings=findings, raw=data, reference_url=ref,
                            source_confidence="observation de scan tierce")
