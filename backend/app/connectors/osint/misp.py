"""MISP instance (restSearch on attributes). Requires an authorised MISP API key."""

from __future__ import annotations

from datetime import UTC, datetime

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Campaign, Findings, OsintProvider, ProviderResult, Reputation


class MispProvider(OsintProvider):
    name = "misp"
    display_name = "MISP"
    category = "threat_intel"
    supported_types = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    requires_api_key = True
    secret_fields = ["api_key"]
    upstream_group = "misp"
    reliability = 0.7
    description = "Recherche d'attributs dans une instance MISP autorisée (partage communautaire/sectoriel)."
    settings_schema = {"base_url": "URL de l'instance MISP", "group": "Groupe d'amont (si alimenté par un autre flux)"}

    def is_configured(self) -> bool:
        return bool(self.ctx.settings.get("base_url")) and super().is_configured()

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        base = str(self.ctx.settings["base_url"]).rstrip("/")
        data, _ = await SafeHttpClient().post_json(
            f"{base}/attributes/restSearch",
            json={"returnFormat": "json", "value": value, "limit": 50, "includeEventTags": True},
            headers={"Authorization": self.ctx.secrets["api_key"], "Accept": "application/json"},
        )
        attrs = ((data or {}).get("response") or {}).get("Attribute") or []
        if not attrs:
            return self._result(ind_type, value, "no_data", raw=data, error_message="Absent de MISP")
        actionable = any(a.get("to_ids") for a in attrs)
        latest = max((datetime.fromtimestamp(int(a["timestamp"]), UTC) for a in attrs if str(a.get("timestamp", "")).isdigit()), default=None)
        events = {}
        for a in attrs:
            ev = a.get("Event") or {}
            if ev.get("id") and ev["id"] not in events:
                events[ev["id"]] = Campaign(name=str(ev.get("info") or f"Événement {ev['id']}")[:200],
                                            reference=f"{base}/events/view/{ev['id']}",
                                            source_statement="Événement MISP partagé")
        findings = Findings(
            reputation=Reputation(
                verdict="malicious" if actionable else "suspicious", score=80.0 if actionable else 50.0,
                raw_score=f"{len(attrs)} attribut(s), to_ids={actionable}", report_count=len(attrs), last_reported_at=latest,
                explanation="Attribut marqué 'to_ids' (IOC actionnable)" if actionable else "Présent à titre contextuel",
            ),
            campaigns=list(events.values())[:20],
            tags=sorted({t.get("name", "") for a in attrs for t in (a.get("Tag") or []) if t.get("name")})[:30],
        )
        return self._result(ind_type, value, "ok", findings=findings, raw=data,
                            reference_url=next(iter(events.values())).reference if events else None,
                            data_updated_at=latest, source_confidence="partage MISP")
