"""crt.sh, Certificate Transparency logs (publicly observable TLS certificates)."""

from __future__ import annotations

from app.connectors.http import SafeHttpClient
from app.connectors.osint.base import Certificate, Findings, OsintProvider, ProviderResult, RelatedIndicator
from app.core.timeutil import parse_timestamp, utc_now


class CrtShProvider(OsintProvider):
    name = "crtsh"
    display_name = "crt.sh (Certificate Transparency)"
    category = "infrastructure"
    supported_types = {"domain"}
    upstream_group = "ct-logs"
    reliability = 0.8
    terms_url = "https://crt.sh/"
    description = "Certificats TLS publiés dans les journaux CT et noms associés (SAN). Sans clé."

    async def _lookup(self, ind_type: str, value: str) -> ProviderResult:
        data, _ = await SafeHttpClient(timeout=40).get_json("https://crt.sh/", params={"q": value, "output": "json"})
        ref = f"https://crt.sh/?q={value}"
        if not data:
            return self._result(ind_type, value, "no_data", reference_url=ref, error_message="Aucun certificat CT")
        rows = sorted(data, key=lambda r: r.get("entry_timestamp") or "", reverse=True)[:50]
        now = utc_now()
        findings = Findings()
        related: dict[str, RelatedIndicator] = {}
        for r in rows:
            sans = sorted({s.strip().lower().lstrip("*.") for s in str(r.get("name_value", "")).splitlines() if s.strip()})
            nb, na = parse_timestamp(r.get("not_before")), parse_timestamp(r.get("not_after"))
            findings.certificates.append(Certificate(
                subject_cn=r.get("common_name"), issuer=r.get("issuer_name"), sans=sans[:50],
                not_before=nb, not_after=na, reference_url=f"https://crt.sh/?id={r.get('id')}",
            ))
            for san in sans:
                if san != value and san not in related:
                    related[san] = RelatedIndicator(
                        type="domain", value=san,
                        relation="certificate_shared_san_current" if na and na > now else "certificate_shared_san_historical",
                        first_seen=nb, last_seen=na,
                    )
        findings.related = list(related.values())[:100]
        findings.notes.append("Un certificat partagé indique un lien d'administration possible, pas une participation à une attaque.")
        return self._result(ind_type, value, "ok", findings=findings, raw=rows, reference_url=ref,
                            data_updated_at=parse_timestamp(rows[0].get("entry_timestamp")) if rows else None)
