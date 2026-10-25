"""RDAP (Registration Data Access Protocol) — registration of IP blocks and domains.

Uses the rdap.org bootstrap redirector, which forwards to the authoritative RIR /
registry. Only organisation-level entities are kept: personal contact data
(individual names, e-mails, phone numbers) is deliberately discarded.
"""

from __future__ import annotations

from typing import Any

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Findings, NetworkInfo, OsintProvider, ProviderResult, RelatedIndicator
from app.core.timeutil import parse_timestamp


def _vcard(entity: dict[str, Any], field: str) -> str | None:
    card = entity.get("vcardArray")
    if not isinstance(card, list) or len(card) < 2:
        return None
    for item in card[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] == field:
            return str(item[3]) if not isinstance(item[3], list) else " ".join(map(str, item[3]))
    return None


def _org_entities(entities: list[dict[str, Any]], roles: set[str]) -> list[str]:
    names: list[str] = []
    for ent in entities or []:
        if not roles.intersection(ent.get("roles") or []):
            continue
        kind = (_vcard(ent, "kind") or "org").lower()
        if kind != "org":
            continue  # never keep individuals
        name = _vcard(ent, "fn")
        if name:
            names.append(name)
    return names


def _event(data: dict[str, Any], action: str):  # noqa: ANN202
    for ev in data.get("events") or []:
        if ev.get("eventAction") == action:
            return parse_timestamp(ev.get("eventDate"))
    return None


class RdapProvider(OsintProvider):
    name = "rdap"
    display_name = "RDAP (registres RIR / registrars)"
    category = "network"
    supported_types = {"ipv4", "ipv6", "domain"}
    upstream_group = "rir-registry"
    reliability = 0.85
    terms_url = "https://about.rdap.org/"
    description = "Données d'enregistrement officielles (RIR pour les IP, registres pour les domaines). Sans clé."
    maturity = "implemented-mock-tested"
    BASE = "https://rdap.org"

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        path = "ip" if ind_type in ("ipv4", "ipv6") else "domain"
        url = f"{self.ctx.settings.get('base_url') or self.BASE}/{path}/{value}"
        data, resp = await SafeHttpClient().get_json(url, headers={"Accept": "application/rdap+json"})
        if not data:
            return self._result(ind_type, value, "no_data", reference_url=url, error_message="Aucun enregistrement RDAP")
        ref = next((lk.get("href") for lk in data.get("links") or [] if lk.get("rel") == "self"), str(resp.url))
        findings = Findings()
        if path == "ip":
            cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in data.get("cidr0_cidrs") or []]
            orgs = _org_entities(data.get("entities") or [], {"registrant"})
            findings.network = NetworkInfo(
                registered_org=orgs[0] if orgs else None,
                network_name=data.get("name"),
                cidr=cidrs[0] if cidrs else (
                    f"{data.get('startAddress')} - {data.get('endAddress')}" if data.get("startAddress") else None
                ),
                rir=(data.get("port43") or "").replace("whois.", "").split(".")[0].upper() or None,
                registration_country=data.get("country"),
                registered_at=_event(data, "registration"),
                updated_at=_event(data, "last changed"),
            )
            if not orgs:
                findings.notes.append("Organisation enregistrée non publiée sous forme d'entité 'org' dans RDAP.")
        else:
            registrars = _org_entities(data.get("entities") or [], {"registrar"})
            for ns in data.get("nameservers") or []:
                if ns.get("ldhName"):
                    findings.related.append(RelatedIndicator(type="domain", value=ns["ldhName"].lower().rstrip("."), relation="nameserver_declared"))
            created = _event(data, "registration")
            findings.notes.append(f"Registrar: {registrars[0] if registrars else 'non publié'}")
            if created:
                findings.notes.append(f"Domaine enregistré le {created.date().isoformat()}")
            findings.tags.extend(s for s in data.get("status") or [] if isinstance(s, str))
        return self._result(
            ind_type, value, "ok", findings=findings, raw=data, reference_url=ref,
            data_updated_at=_event(data, "last changed"), source_confidence="registre faisant autorité",
        )
