"""Synthetic OSINT sources for DEMO MODE ONLY.

These providers never contact any service. Their output is derived
deterministically from a hash of the indicator and uses only reserved values:
documentation ASNs (RFC 5398: AS64496-AS64511), user-assigned ISO country codes
(XA, XB, ZZ), ``.example`` domains and coordinates in the open Atlantic Ocean.
Every result is flagged ``is_synthetic`` and labelled "DONNÉE DE DÉMONSTRATION".

Two demo reputation feeds deliberately share the same upstream group to
demonstrate that the confidence engine does not count duplicated sources twice,
and the two demo geolocation sources disagree to demonstrate contradiction handling.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

from app.connectors.osint.base import (
    Campaign, Certificate, ExposedServices, Findings, GeoInfo, NetworkInfo, OsintProvider, ProviderResult,
    RelatedIndicator, Reputation, Resolution,
)
from app.core.timeutil import utc_now

DEMO_LABEL = "DONNÉE DE DÉMONSTRATION"
ALL = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}


def _h(value: str, salt: str) -> int:
    return int(hashlib.sha256(f"{salt}:{value}".encode()).hexdigest(), 16)


class _Demo(OsintProvider):
    is_synthetic_provider = True
    maturity = "demo-synthetic"
    reliability = 0.6

    def _ok(self, t: str, v: str, findings: Findings, **kw) -> ProviderResult:  # noqa: ANN003
        findings.notes.insert(0, f"{DEMO_LABEL} — générée localement, aucune source réelle interrogée.")
        return self._result(t, v, "ok", findings=findings, raw={"synthetic": True, "label": DEMO_LABEL},
                            reference_url=None, source_confidence="synthétique", **kw)


class DemoNetworkProvider(_Demo):
    name = "demo_network"
    display_name = "[DÉMO] Registre réseau synthétique"
    category = "network"
    supported_types = {"ipv4", "ipv6"}
    upstream_group = "demo-registry"
    reliability = 0.85
    description = "Organisation/ASN synthétiques (ASN de documentation RFC 5398)."

    async def _lookup(self, t: str, v: str) -> ProviderResult:
        h = _h(v, "net")
        asn = 64496 + h % 16
        n = h % 900 + 100
        return self._ok(t, v, Findings(network=NetworkInfo(
            registered_org=f"ORGANISATION-DÉMO-{n} (synthétique)", network_name=f"DEMO-NET-{n}",
            asn=asn, as_name=f"DEMO-AS-{asn} (synthétique)", isp=f"FAI-DÉMO-{h % 7} (synthétique)",
            cidr=None, rir="DEMO", registration_country="ZZ",
        )), data_updated_at=utc_now() - timedelta(days=h % 400))


class _DemoGeo(_Demo):
    category = "geolocation"
    supported_types = {"ipv4", "ipv6"}
    salt = "geo"
    country_code = "XA"

    async def _lookup(self, t: str, v: str) -> ProviderResult:
        h = _h(v, self.salt)
        # open Atlantic Ocean (Gulf of Guinea offshore): clearly not a real location
        lat = -5 + (h % 800) / 100
        lon = -10 + (h // 800 % 900) / 100
        return self._ok(t, v, Findings(geo=GeoInfo(
            country=f"Pays synthétique {self.country_code}", country_code=self.country_code,
            region="Région de démonstration", city=None, latitude=round(lat, 2), longitude=round(lon, 2),
            accuracy_radius_km=float(100 + h % 400),
            precision_note="Coordonnées fictives (océan) — démonstration uniquement.",
        )))


class DemoGeoAProvider(_DemoGeo):
    name = "demo_geo_a"
    display_name = "[DÉMO] Géolocalisation synthétique A"
    upstream_group = "demo-geo-a"
    description = "Géolocalisation fictive."
    salt, country_code = "geo-a", "XA"


class DemoGeoBProvider(_DemoGeo):
    name = "demo_geo_b"
    display_name = "[DÉMO] Géolocalisation synthétique B"
    upstream_group = "demo-geo-b"
    description = "Géolocalisation fictive, volontairement contradictoire avec A."
    salt, country_code = "geo-b", "XB"


class _DemoRep(_Demo):
    category = "reputation"
    supported_types = ALL
    salt = "rep"

    async def _lookup(self, t: str, v: str) -> ProviderResult:
        h = _h(v, self.salt)
        score = float(h % 100)
        verdict = "malicious" if score >= 70 else "suspicious" if score >= 35 else "unknown"
        return self._ok(t, v, Findings(reputation=Reputation(
            verdict=verdict, score=score, raw_score=f"{int(score)}/100 (synthétique)", report_count=h % 40,
            last_reported_at=utc_now() - timedelta(days=h % 120),
            categories=["demo-bruteforce"] if verdict != "unknown" else [],
            explanation="Score synthétique dérivé d'un hachage — sans valeur de renseignement.",
        )), data_updated_at=utc_now() - timedelta(days=h % 120))


class DemoReputationAProvider(_DemoRep):
    name = "demo_reputation_a"
    display_name = "[DÉMO] Flux de réputation A"
    upstream_group = "demo-feed-1"
    reliability = 0.7
    description = "Réputation fictive (amont : demo-feed-1)."
    salt = "rep-1"


class DemoReputationMirrorProvider(_DemoRep):
    name = "demo_reputation_mirror"
    display_name = "[DÉMO] Flux miroir de A"
    upstream_group = "demo-feed-1"
    reliability = 0.5
    description = "Rediffuse le flux A : démontre la prise en compte de la dépendance entre sources."
    salt = "rep-1"


class DemoReputationBProvider(_DemoRep):
    name = "demo_reputation_b"
    display_name = "[DÉMO] Flux de réputation B (indépendant)"
    upstream_group = "demo-feed-2"
    reliability = 0.7
    description = "Réputation fictive d'un amont indépendant."
    salt = "rep-2"


class DemoInfrastructureProvider(_Demo):
    name = "demo_infrastructure"
    display_name = "[DÉMO] Infrastructure associée"
    category = "infrastructure"
    supported_types = {"ipv4", "ipv6", "domain"}
    upstream_group = "demo-passive-dns"
    description = "Résolutions, certificats, services et campagnes fictifs (.example)."

    async def _lookup(self, t: str, v: str) -> ProviderResult:
        h = _h(v, "infra")
        now = utc_now()
        d1, d2 = f"portail-{h % 97}.demo.example", f"cdn-{h % 89}.demo.example"
        old = now - timedelta(days=200 + h % 100)
        f = Findings(
            resolutions=[
                Resolution(type="A", value=d1, first_seen=now - timedelta(days=10), last_seen=now, temporality="current"),
                Resolution(type="A", value=d2, first_seen=old - timedelta(days=60), last_seen=old, temporality="historical"),
            ],
            related=[
                RelatedIndicator(type="domain", value=d1, relation="passive_dns_current", first_seen=now - timedelta(days=10), last_seen=now),
                RelatedIndicator(type="domain", value=d2, relation="passive_dns_historical", first_seen=old - timedelta(days=60), last_seen=old),
            ],
            certificates=[Certificate(subject_cn=d1, issuer="CN=Autorité de démonstration", sans=[d1, d2],
                                      not_before=now - timedelta(days=30), not_after=now + timedelta(days=60))],
            services=ExposedServices(ports=sorted({22, 80, 443, [3389, 8080, 5900][h % 3]}), tags=["demo"]),
        )
        if h % 3 == 0:
            f.campaigns.append(Campaign(name="CAMPAGNE-DÉMO-ALPHA (fictive)", reference=None,
                                        source_statement="Association déclarée par une source synthétique"))
        return self._ok(t, v, f)


DEMO_PROVIDERS: list[type[OsintProvider]] = [
    DemoNetworkProvider, DemoGeoAProvider, DemoGeoBProvider, DemoReputationAProvider,
    DemoReputationMirrorProvider, DemoReputationBProvider, DemoInfrastructureProvider,
]
