"""GreyNoise Community API — Internet background noise / known benign services."""

from __future__ import annotations

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Findings, OsintProvider, ProviderResult, Reputation
from app.core.timeutil import parse_timestamp


class GreyNoiseProvider(OsintProvider):
    name = "greynoise"
    display_name = "GreyNoise Community"
    category = "reputation"
    supported_types = {"ipv4"}
    upstream_group = "greynoise-sensors"
    reliability = 0.75
    terms_url = "https://www.greynoise.io/terms"
    description = "Indique si l'IP scanne massivement Internet (bruit de fond) ou est un service connu (RIOT)."
    secret_fields = ["api_key"]

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        headers = {"key": self.ctx.secrets["api_key"]} if self.ctx.secrets.get("api_key") else {}
        data, resp = await SafeHttpClient().get_json(f"https://api.greynoise.io/v3/community/{value}", headers=headers)
        ref = f"https://viz.greynoise.io/ip/{value}"
        if resp.status_code == 404 or not data or not (data.get("noise") or data.get("riot")):
            return self._result(ind_type, value, "no_data", raw=data, reference_url=ref,
                                error_message="Non observé par les capteurs GreyNoise")
        classification = data.get("classification") or "unknown"
        verdict = {"malicious": "malicious", "benign": "benign"}.get(classification, "unknown")
        if data.get("riot"):
            verdict = "benign"
        findings = Findings(
            reputation=Reputation(
                verdict=verdict, score={"malicious": 80.0, "benign": 0.0}.get(verdict),
                raw_score=f"classification={classification}", last_reported_at=parse_timestamp(data.get("last_seen")),
                explanation=("Scanner Internet opportuniste observé (bruit de fond)." if data.get("noise") else "")
                + (" Service d'entreprise connu (RIOT)." if data.get("riot") else ""),
            ),
            tags=[t for t, flag in (("internet-scanner", data.get("noise")), ("known-service", data.get("riot"))) if flag],
        )
        if data.get("name") and data.get("name") != "unknown":
            findings.notes.append(f"Acteur/service déclaré par GreyNoise : {data['name']}")
        return self._result(ind_type, value, "ok", findings=findings, raw=data, reference_url=data.get("link") or ref,
                            data_updated_at=parse_timestamp(data.get("last_seen")), source_confidence=classification)
