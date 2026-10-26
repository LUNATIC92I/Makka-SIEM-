"""Serialisation helpers (DB -> JSON for the API). Secrets are never serialised."""

from __future__ import annotations

from typing import Any

from app.connectors.osint.registry import CATALOG
from app.connectors.siem.connectors import SIEM_CONNECTORS
from app.core.timeutil import iso
from app.models import (
    AIAnalysis, ConnectorConfig, EnrichmentResult, IndicatorRelation, Investigation, InvestigationIndicator,
    InvestigationNote, Report, SiemEvent, Task, User,
)
from app.security.secrets_vault import masked

MATURITY_LABELS = {
    "implemented-tested": "Implémenté et testé",
    "implemented-mock-tested": "Implémenté — testé sur réponses simulées, non validé sur instance réelle",
    "demo-synthetic": "Source synthétique (démonstration)",
}


def user_out(u: User) -> dict[str, Any]:
    return {"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role.name,
            "permissions": u.role.permissions, "is_active": u.is_active, "created_at": iso(u.created_at),
            "last_login_at": iso(u.last_login_at), "locked": bool(u.locked_until)}


def event_out(e: SiemEvent, with_raw: bool = False) -> dict[str, Any]:
    d = {
        "id": e.id, "source_system": e.source_system, "original_id": e.original_id, "ingest_method": e.ingest_method,
        "received_at": iso(e.received_at), "event_time": iso(e.event_time), "title": e.title, "event_type": e.event_type,
        "severity": e.severity, "severity_raw": e.severity_raw, "src_ip": e.src_ip, "dst_ip": e.dst_ip,
        "src_port": e.src_port, "dst_port": e.dst_port, "protocol": e.protocol, "hostname": e.hostname,
        "attempt_count": e.attempt_count, "context": e.context, "raw_sha256": e.raw_sha256, "is_synthetic": e.is_synthetic,
    }
    if with_raw:
        d["raw"] = e.raw
    return d


def investigation_summary(inv: Investigation) -> dict[str, Any]:
    first = inv.events[0] if inv.events else None
    return {
        "id": inv.id, "reference": inv.reference, "title": inv.title, "status": inv.status, "priority": inv.priority,
        "severity": inv.severity, "source_system": inv.source_system, "restricted": inv.restricted,
        "pipeline_status": inv.pipeline_status, "risk_score": inv.risk_score, "risk_level": inv.risk_level,
        "confidence_score": inv.confidence_score, "confidence_level": inv.confidence_level,
        "is_synthetic": inv.is_synthetic, "created_at": iso(inv.created_at), "updated_at": iso(inv.updated_at),
        "owner": inv.owner.username if inv.owner else None, "assignees": [u.username for u in inv.assignees],
        "event_count": len(inv.events), "src_ip": first.src_ip if first else None,
        "target": (first.hostname or first.dst_ip) if first else None,
    }


def link_out(link: InvestigationIndicator) -> dict[str, Any]:
    i = link.indicator
    return {"id": i.id, "type": i.type, "value": i.value, "scope": i.scope, "note": i.classification.get("note"),
            "role": link.role, "extracted_from": link.extracted_from, "event_id": link.event_id}


def result_out(r: EnrichmentResult, with_raw: bool = False) -> dict[str, Any]:
    cls = CATALOG.get(r.source_name)
    d = {
        "id": r.id, "evidence_id": f"R{r.id}", "indicator": r.indicator.value, "indicator_type": r.indicator.type,
        "source": r.source_name, "source_display": cls.display_name if cls else r.source_name,
        "category": cls.category if cls else None, "upstream_group": cls.upstream_group if cls else None,
        "reliability": cls.reliability if cls else None, "status": r.status, "queried_at": iso(r.queried_at),
        "data_updated_at": iso(r.data_updated_at), "duration_ms": r.duration_ms, "findings": r.findings,
        "reference_url": r.reference_url, "source_confidence": r.source_confidence,
        "error_message": r.error_message or (None if r.status == "ok" else "Donnée indisponible"),
        "access_notes": r.access_notes, "raw_sha256": r.raw_sha256, "is_synthetic": r.is_synthetic,
        "run_number": r.run_number, "superseded_at": iso(r.superseded_at),
    }
    if with_raw:
        d["raw"] = r.raw
    return d


def relation_out(r: IndicatorRelation) -> dict[str, Any]:
    return {"id": r.id, "from_kind": r.from_kind, "from_value": r.from_value, "to_kind": r.to_kind, "to_value": r.to_value,
            "relation_type": r.relation_type, "source": r.source_name, "observed_at": iso(r.observed_at),
            "temporality": r.temporality, "confidence": r.confidence,
            "evidence_id": f"R{r.evidence_result_id}" if r.evidence_result_id else None, "is_synthetic": r.is_synthetic}


def analysis_out(a: AIAnalysis) -> dict[str, Any]:
    return {"id": a.id, "provider": a.provider, "model": a.model, "status": a.status, "created_at": iso(a.created_at),
            "output": a.output, "validation_issues": a.validation_issues, "injection_flags": a.injection_flags,
            "input_sha256": a.input_sha256, "data_sent_externally": a.data_sent_externally, "error_message": a.error_message}


def note_out(n: InvestigationNote) -> dict[str, Any]:
    return {"id": n.id, "kind": n.kind, "content": n.content, "created_at": iso(n.created_at),
            "author": n.user.username if n.user else "système"}


def report_out(r: Report) -> dict[str, Any]:
    return {"id": r.id, "investigation_id": r.investigation_id, "kind": r.kind, "format": r.format, "file_name": r.file_name,
            "sha256": r.sha256, "size_bytes": r.size_bytes, "created_at": iso(r.created_at)}


def task_out(t: Task) -> dict[str, Any]:
    return {"id": t.id, "type": t.type, "payload": t.payload, "status": t.status, "attempts": t.attempts,
            "max_attempts": t.max_attempts, "next_run_at": iso(t.next_run_at), "last_error": t.last_error,
            "result": t.result, "created_at": iso(t.created_at), "finished_at": iso(t.finished_at)}


def connector_out(c: ConnectorConfig) -> dict[str, Any]:
    meta: dict[str, Any] = {}
    if c.kind == "osint" and c.provider in CATALOG:
        cls = CATALOG[c.provider]
        meta = {"display_name": cls.display_name, "category": cls.category, "description": cls.description,
                "requires_api_key": cls.requires_api_key, "secret_fields": cls.secret_fields,
                "settings_schema": cls.settings_schema, "terms_url": cls.terms_url, "reliability": cls.reliability,
                "upstream_group": cls.upstream_group, "maturity": MATURITY_LABELS.get(cls.maturity, cls.maturity),
                "supported_types": sorted(cls.supported_types)}
    elif c.kind == "siem" and c.provider in SIEM_CONNECTORS:
        cls = SIEM_CONNECTORS[c.provider]
        meta = {"display_name": cls.display_name, "description": cls.description, "secret_fields": cls.secret_fields,
                "settings_schema": cls.settings_schema, "maturity": MATURITY_LABELS.get(cls.maturity, cls.maturity)}
    elif c.kind == "notification":
        from app.services.notifications import EMAIL_SECRETS, EMAIL_SETTINGS, PROVIDERS, SECRET_FIELDS, SETTINGS_SCHEMA

        email = c.provider == "email"
        meta = {"display_name": PROVIDERS.get(c.provider, c.provider),
                "settings_schema": EMAIL_SETTINGS if email else SETTINGS_SCHEMA,
                "secret_fields": EMAIL_SECRETS if email else SECRET_FIELDS, "description": "Notification sortante au franchissement d'un seuil de risque."}
    secrets = masked(c.secret_ciphertext)
    # "operational" only when configured, enabled and the last real run succeeded.
    if not c.enabled:
        state = "désactivé"
    elif meta.get("requires_api_key") and not secrets:
        state = "non configuré"
    elif c.last_status == "ok":
        state = "opérationnel (dernier test réussi)"
    elif c.last_status == "error":
        state = "en erreur"
    else:
        state = "activé — jamais testé"
    return {"id": c.id, "kind": c.kind, "provider": c.provider, "name": c.name, "enabled": c.enabled,
            "settings": c.settings, "secrets": secrets, "poll_interval_seconds": c.poll_interval_seconds,
            "last_status": c.last_status, "last_error": c.last_error, "last_success_at": iso(c.last_success_at),
            "last_run_at": iso(c.last_run_at), "state": state, **meta}
