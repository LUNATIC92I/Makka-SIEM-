"""Live DNS resolution (passive: standard recursive queries, no zone transfer, no brute force)."""

from __future__ import annotations

import asyncio

from app.connectors.osint.base import Findings, OsintProvider, ProviderResult, RelatedIndicator, Resolution
from app.core.errors import ConnectorError


class DnsProvider(OsintProvider):
    name = "dns"
    display_name = "Résolution DNS (temps réel)"
    category = "infrastructure"
    supported_types = {"domain", "ipv4", "ipv6"}
    upstream_group = "dns-live"
    reliability = 0.9
    description = "Enregistrements A/AAAA/CNAME/MX/NS actuels et PTR inverse via le résolveur configuré."
    settings_schema = {"nameservers": "Résolveurs (séparés par des virgules, optionnel)"}

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        return await asyncio.to_thread(self._resolve, ind_type, value)

    def _resolve(self, ind_type: str, value: str) -> ProviderResult:
        import dns.exception
        import dns.resolver
        import dns.reversename

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8.0
        ns = self.ctx.settings.get("nameservers")
        if ns:
            resolver.nameservers = [s.strip() for s in str(ns).split(",") if s.strip()]
        findings = Findings()
        raw: dict[str, list[str]] = {}
        queries = [(dns.reversename.from_address(value), "PTR")] if ind_type != "domain" else [
            (value, t) for t in ("A", "AAAA", "CNAME", "MX", "NS")
        ]
        errors = 0
        for qname, rtype in queries:
            try:
                answer = resolver.resolve(qname, rtype, raise_on_no_answer=False)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                raw[rtype] = []
                continue
            except dns.exception.DNSException:
                errors += 1
                continue
            values = [r.to_text().rstrip(".") for r in answer] if answer.rrset else []
            raw[rtype] = values
            for v in values:
                target = v.split()[-1].lower() if rtype == "MX" else v.lower()
                findings.resolutions.append(Resolution(type=rtype, value=target, temporality="current"))
                if rtype in ("A", "AAAA"):
                    findings.related.append(RelatedIndicator(type="ipv4" if rtype == "A" else "ipv6", value=target, relation="dns_resolution_observed"))
                elif rtype in ("CNAME", "MX", "NS", "PTR"):
                    findings.related.append(RelatedIndicator(type="domain", value=target, relation=f"dns_{rtype.lower()}_observed"))
        if errors == len(queries):
            raise ConnectorError("Résolveur DNS injoignable", retryable=True)
        if not findings.resolutions:
            return self._result(ind_type, value, "no_data", raw=raw, error_message="Aucun enregistrement DNS")
        findings.notes.append("Résolution actuelle : ne prouve pas que le domaine et l'IP participent à la même activité.")
        return self._result(ind_type, value, "ok", findings=findings, raw=raw, source_confidence="observation directe")
