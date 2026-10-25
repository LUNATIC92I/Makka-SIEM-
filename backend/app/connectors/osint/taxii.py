"""STIX 2.1 / TAXII 2.1 collection.

TAXII 2.1 does not support server-side filtering by indicator value, so the
collection's ``indicator`` objects are fetched (paginated, bounded) and cached
in memory for ``cache_minutes``; patterns are then matched locally.
"""

from __future__ import annotations

import re
import time
from typing import Any

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Campaign, Findings, OsintProvider, ProviderResult, Reputation
from app.core.errors import ConnectorError
from app.core.timeutil import parse_timestamp

_CACHE: dict[str, tuple[float, list[dict[str, Any]]]] = {}
TAXII_ACCEPT = "application/taxii+json;version=2.1"


class TaxiiProvider(OsintProvider):
    name = "taxii"
    display_name = "Flux STIX/TAXII 2.1"
    category = "threat_intel"
    supported_types = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    upstream_group = "taxii"
    reliability = 0.7
    description = "Indicateurs STIX d'une collection TAXII 2.1 autorisée."
    settings_schema = {"api_root": "URL de l'API root TAXII", "collection_id": "ID de collection", "cache_minutes": "60"}
    secret_fields = ["token", "username", "password"]

    def is_configured(self) -> bool:
        return bool(self.ctx.settings.get("api_root") and self.ctx.settings.get("collection_id"))

    async def _objects(self) -> list[dict[str, Any]]:
        url = f"{str(self.ctx.settings['api_root']).rstrip('/')}/collections/{self.ctx.settings['collection_id']}/objects/"
        ttl = float(self.ctx.settings.get("cache_minutes") or 60) * 60
        cached = _CACHE.get(url)
        if cached and time.time() - cached[0] < ttl:
            return cached[1]
        kwargs: dict[str, Any] = {"headers": {"Accept": TAXII_ACCEPT}}
        if self.ctx.secrets.get("token"):
            kwargs["headers"]["Authorization"] = f"Bearer {self.ctx.secrets['token']}"
        elif self.ctx.secrets.get("username"):
            kwargs["auth"] = (self.ctx.secrets["username"], self.ctx.secrets.get("password", ""))
        objects: list[dict[str, Any]] = []
        params: dict[str, Any] = {"match[type]": "indicator", "limit": 1000}
        http = SafeHttpClient(timeout=60)
        for _page in range(20):
            data, _ = await http.get_json(url, params=params, **kwargs)
            if not isinstance(data, dict):
                raise ConnectorError("Réponse TAXII invalide")
            objects.extend(o for o in data.get("objects") or [] if o.get("type") == "indicator")
            if not data.get("more") or not data.get("next"):
                break
            params["next"] = data["next"]
        _CACHE[url] = (time.time(), objects)
        return objects

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        objects = await self._objects()
        needle = re.compile(r"'" + re.escape(value) + r"'", re.IGNORECASE)
        hits = [o for o in objects if needle.search(str(o.get("pattern", "")))]
        if not hits:
            return self._result(ind_type, value, "no_data", error_message="Absent de la collection TAXII")
        latest = max((parse_timestamp(o.get("modified")) for o in hits), default=None, key=lambda d: d.timestamp() if d else 0)
        findings = Findings(
            reputation=Reputation(
                verdict="malicious", score=75.0, report_count=len(hits), last_reported_at=latest,
                raw_score=f"{len(hits)} indicateur(s) STIX",
                categories=sorted({str(lbl) for o in hits for lbl in (o.get("indicator_types") or o.get("labels") or [])}),
                explanation="Présent comme indicateur STIX dans la collection configurée.",
            ),
            campaigns=[Campaign(name=str(o.get("name") or o.get("id"))[:200], reference=o.get("id"),
                                source_statement="Indicateur STIX (objet de la collection)") for o in hits[:10]],
        )
        return self._result(ind_type, value, "ok", findings=findings, raw=hits[:20], data_updated_at=latest,
                            source_confidence=str(hits[0].get("confidence", "non communiquée")))
