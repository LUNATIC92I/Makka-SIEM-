"""Builds the evidence package given to the AI: minimal, sanitised, with stable evidence IDs.

* ``E<n>``: SIEM events; ``R<id>``: OSINT enrichment results; ``C<n>``: correlation items.
* Raw payloads are NOT included (data minimisation). Internal host names and
  private addresses can be pseudonymised before leaving the workstation.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.core.timeutil import iso
from app.models import EnrichmentResult, Investigation, InvestigationIndicator, SiemEvent
from app.security.sanitize import clean_text, sanitize_structure, scan_structure


class Pseudonymizer:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.mapping: dict[str, str] = {}

    def __call__(self, value: str | None, kind: str) -> str | None:
        if not value or not self.enabled:
            return value
        if value not in self.mapping:
            self.mapping[value] = f"{kind}-{sum(1 for k in self.mapping.values() if k.startswith(kind)) + 1}"
        return self.mapping[value]


def build_evidence(
    inv: Investigation, events: list[SiemEvent], links: list[InvestigationIndicator],
    results: list[EnrichmentResult], *, pseudonymize: bool,
) -> dict[str, Any]:
    pseudo = Pseudonymizer(pseudonymize)
    scope_by_value = {link.indicator.value: link.indicator.scope for link in links}

    def ip(v: str | None) -> str | None:
        if v and scope_by_value.get(v, "public") != "public":
            return pseudo(v, "IP-INTERNE")
        return v

    package: dict[str, Any] = {
        "investigation": {"reference": inv.reference, "title": clean_text(inv.title, 300), "synthetic_data": inv.is_synthetic},
        "events": [
            {
                "id": f"E{i + 1}", "source_system": e.source_system, "original_id": e.original_id,
                "time_utc": iso(e.event_time), "title": clean_text(e.title, 300), "event_type": clean_text(e.event_type, 100),
                "severity": e.severity, "src_ip": ip(e.src_ip), "dst_ip": ip(e.dst_ip), "src_port": e.src_port,
                "dst_port": e.dst_port, "protocol": e.protocol, "target_host": pseudo(e.hostname, "HOTE"),
                "attempt_count": e.attempt_count, "synthetic_data": e.is_synthetic,
            }
            for i, e in enumerate(events)
        ],
        "indicators": [
            {"type": link.indicator.type, "value": ip(link.indicator.value) if link.indicator.type in ("ipv4", "ipv6") else link.indicator.value,
             "role": link.role, "scope": link.indicator.scope, "scope_note": link.indicator.classification.get("note")}
            for link in links
        ],
        "osint_results": [
            {
                "id": f"R{r.id}", "source": r.source_name, "indicator": r.indicator.value, "status": r.status,
                "queried_at_utc": iso(r.queried_at), "data_updated_at_utc": iso(r.data_updated_at),
                "reference_url": r.reference_url, "findings": sanitize_structure(r.findings, max_str=500),
                "error": r.error_message, "synthetic_data": r.is_synthetic,
            }
            for r in results
        ],
        "correlation": sanitize_structure(inv.correlation or {}, max_str=600),
        "scoring": {
            k: (inv.scoring or {}).get(k)
            for k in ("risk_score", "risk_level", "confidence_score", "confidence_level", "risk_factors",
                      "confidence_factors", "notes")
        },
    }
    package["allowed_evidence_ids"] = [e["id"] for e in package["events"]] + [r["id"] for r in package["osint_results"]]
    package["allowed_reference_urls"] = sorted({r["reference_url"] for r in package["osint_results"] if r["reference_url"]})
    return package


def evidence_digest(package: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(package, sort_keys=True, default=str).encode()).hexdigest()


def injection_flags(package: dict[str, Any]) -> list[dict[str, str]]:
    return scan_structure({k: package[k] for k in ("events", "indicators", "osint_results")})
