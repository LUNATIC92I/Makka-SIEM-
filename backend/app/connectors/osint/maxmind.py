"""MaxMind GeoLite2 / GeoIP2 local databases (offline, no data leaves the workstation)."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from app.connectors.osint.base import Findings, GeoInfo, NetworkInfo, OsintProvider, ProviderResult
from app.core.errors import ConnectorError


class MaxMindProvider(OsintProvider):
    name = "maxmind"
    display_name = "MaxMind GeoLite2 (base locale)"
    category = "geolocation"
    supported_types = {"ipv4", "ipv6"}
    upstream_group = "geo-maxmind"
    reliability = 0.6
    terms_url = "https://www.maxmind.com/en/geolite2/eula"
    description = "Bases .mmdb locales (City/ASN). Aucune requête réseau ; licence MaxMind requise."
    settings_schema = {"city_db_path": "Chemin GeoLite2-City.mmdb", "asn_db_path": "Chemin GeoLite2-ASN.mmdb"}

    def is_configured(self) -> bool:
        return bool(self.ctx.settings.get("city_db_path") or self.ctx.settings.get("asn_db_path"))

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        import maxminddb

        findings = Findings()
        raw: dict = {}
        build: datetime | None = None
        for key in ("city_db_path", "asn_db_path"):
            path = self.ctx.settings.get(key)
            if not path:
                continue
            if not Path(path).is_file():
                raise ConnectorError(f"Base MaxMind introuvable ({key})")
            with maxminddb.open_database(path) as reader:
                rec = reader.get(value) or {}
                build = datetime.fromtimestamp(reader.metadata().build_epoch, UTC)
            raw[key] = rec
            if key == "city_db_path" and rec:
                loc = rec.get("location") or {}
                subs = rec.get("subdivisions") or [{}]
                findings.geo = GeoInfo(
                    country_code=(rec.get("country") or {}).get("iso_code"),
                    country=((rec.get("country") or {}).get("names") or {}).get("fr")
                    or ((rec.get("country") or {}).get("names") or {}).get("en"),
                    region=(subs[0].get("names") or {}).get("en"),
                    city=((rec.get("city") or {}).get("names") or {}).get("en"),
                    latitude=loc.get("latitude"), longitude=loc.get("longitude"),
                    accuracy_radius_km=loc.get("accuracy_radius"),
                    precision_note="Rayon de précision déclaré par MaxMind (km).",
                )
            if key == "asn_db_path" and rec:
                findings.network = NetworkInfo(
                    asn=rec.get("autonomous_system_number"), as_name=rec.get("autonomous_system_organization")
                )
        if not findings.geo and not findings.network:
            return self._result(ind_type, value, "no_data", raw=raw, data_updated_at=build,
                                error_message="Adresse absente des bases locales")
        return self._result(ind_type, value, "ok", findings=findings, raw=raw, data_updated_at=build,
                            source_confidence="base locale (date de build indiquée)",
                            access_notes="Base locale : vérifier sa fraîcheur (date de build).")
