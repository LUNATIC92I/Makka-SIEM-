"""AbuseIPDB v2, community abuse reports for IP addresses."""

from __future__ import annotations

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Findings, NetworkInfo, OsintProvider, ProviderResult, Reputation
from app.core.timeutil import parse_timestamp


class AbuseIpDbProvider(OsintProvider):
    name = "abuseipdb"
    display_name = "AbuseIPDB"
    category = "reputation"
    supported_types = {"ipv4", "ipv6"}
    requires_api_key = True
    secret_fields = ["api_key"]
    upstream_group = "abuseipdb"
    reliability = 0.65
    terms_url = "https://www.abuseipdb.com/legal"
    description = "Signalements communautaires d'abus (score de confiance 0-100). Clé API requise."

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        days = int(self.ctx.settings.get("max_age_days") or 90)
        data, _ = await SafeHttpClient().get_json(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": value, "maxAgeInDays": days},
            headers={"Key": self.ctx.secrets["api_key"], "Accept": "application/json"},
        )
        ref = f"https://www.abuseipdb.com/check/{value}"
        d = (data or {}).get("data")
        if not d:
            return self._result(ind_type, value, "no_data", raw=data, reference_url=ref)
        score = float(d.get("abuseConfidenceScore") or 0)
        reports = int(d.get("totalReports") or 0)
        if d.get("isWhitelisted"):
            verdict = "benign"
        elif score >= 75:
            verdict = "malicious"
        elif score >= 25 or reports >= 5:
            verdict = "suspicious"
        else:
            verdict = "unknown"
        findings = Findings(
            reputation=Reputation(
                verdict=verdict, score=score, raw_score=f"{int(score)}/100", report_count=reports,
                last_reported_at=parse_timestamp(d.get("lastReportedAt")),
                categories=[c for c in [d.get("usageType")] if c],
                explanation=f"{reports} signalement(s) sur {days} jours par {d.get('numDistinctUsers', 0)} déclarant(s).",
            ),
            network=NetworkInfo(isp=d.get("isp")),
        )
        if d.get("isTor"):
            findings.tags.append("tor-exit-node")
            findings.notes.append("Nœud de sortie Tor : l'adresse ne désigne pas l'auteur réel.")
        return self._result(ind_type, value, "ok", findings=findings, raw=data, reference_url=ref,
                            data_updated_at=parse_timestamp(d.get("lastReportedAt")),
                            source_confidence=f"abuseConfidenceScore={int(score)}")
