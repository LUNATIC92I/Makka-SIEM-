"""VirusTotal API v3 — multi-engine reputation (aggregator: overlaps other feeds)."""

from __future__ import annotations

import base64
from datetime import UTC, datetime

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Findings, NetworkInfo, OsintProvider, ProviderResult, Reputation


def vt_verdict(stats: dict[str, int], threshold: int = 3) -> tuple[str, float]:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    score = min(100.0, 100.0 * (malicious + 0.5 * suspicious) / 5)
    if malicious >= threshold:
        return "malicious", score
    if malicious >= 1 or suspicious >= 2:
        return "suspicious", score
    # No detection does NOT mean benign: VirusTotal does not assert innocuousness.
    return "unknown", score


class VirusTotalProvider(OsintProvider):
    name = "virustotal"
    display_name = "VirusTotal"
    category = "reputation"
    supported_types = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}
    requires_api_key = True
    secret_fields = ["api_key"]
    upstream_group = "virustotal-aggregate"
    reliability = 0.75
    terms_url = "https://docs.virustotal.com/docs/terms-of-service"
    description = "Agrégateur multi-moteurs. Clé API requise (quota public : 4 req/min)."

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        if ind_type in ("ipv4", "ipv6"):
            path, gui = f"ip_addresses/{value}", f"ip-address/{value}"
        elif ind_type == "domain":
            path, gui = f"domains/{value}", f"domain/{value}"
        elif ind_type == "url":
            vid = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            path, gui = f"urls/{vid}", f"url/{vid}"
        else:
            path, gui = f"files/{value}", f"file/{value}"
        data, _ = await SafeHttpClient().get_json(
            f"https://www.virustotal.com/api/v3/{path}", headers={"x-apikey": self.ctx.secrets["api_key"]}
        )
        ref = f"https://www.virustotal.com/gui/{gui}"
        if not data:
            return self._result(ind_type, value, "no_data", reference_url=ref, error_message="Indicateur inconnu de VirusTotal")
        attrs = (data.get("data") or {}).get("attributes") or {}
        stats = attrs.get("last_analysis_stats") or {}
        verdict, score = vt_verdict(stats, int(self.ctx.settings.get("malicious_threshold") or 3))
        total = sum(int(v) for v in stats.values()) if stats else None
        last = attrs.get("last_analysis_date")
        last_dt = datetime.fromtimestamp(last, UTC) if isinstance(last, (int, float)) else None
        findings = Findings(
            reputation=Reputation(
                verdict=verdict, score=score, raw_score=f"{stats.get('malicious', 0)}/{total or 0} moteurs",
                detections=int(stats.get("malicious", 0)), total_engines=total, last_reported_at=last_dt,
                categories=sorted({str(c) for c in (attrs.get("categories") or {}).values()})[:10],
                explanation="Aucune détection n'implique pas l'innocuité." if verdict == "unknown" else None,
            )
        )
        if ind_type in ("ipv4", "ipv6") and (attrs.get("asn") or attrs.get("as_owner")):
            findings.network = NetworkInfo(asn=attrs.get("asn"), as_name=attrs.get("as_owner"), cidr=attrs.get("network"))
        findings.tags = [str(t) for t in attrs.get("tags") or []][:20]
        return self._result(ind_type, value, "ok", findings=findings, raw=data, reference_url=ref,
                            data_updated_at=last_dt, source_confidence=f"{stats.get('malicious', 0)} moteur(s) malveillant(s)")
