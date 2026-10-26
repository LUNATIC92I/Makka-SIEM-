"""Orchestrates an AI analysis: evidence package -> provider -> validation -> storage."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.evidence import build_evidence, evidence_digest, injection_flags
from app.ai.providers import AIConfig, build_provider
from app.ai.validation import validate_output
from app.core.config import get_settings
from app.core.errors import ConnectorError
from app.investigation.queries import current_results
from app.models import AIAnalysis, ConnectorConfig, EnrichmentResult, Investigation, InvestigationIndicator
from app.security.secrets_vault import decrypt_secrets
from app.services import audit


def resolve_ai_config(db: Session, provider_override: str | None = None) -> AIConfig:
    s = get_settings()
    cfg = AIConfig(
        provider=s.ai_provider, model=s.ai_model, base_url=s.ai_base_url,
        external_processing_allowed=s.ai_external_processing_allowed, pseudonymize=s.ai_pseudonymize,
        timeout=s.ai_timeout_seconds,
    )
    row = db.scalars(select(ConnectorConfig).where(ConnectorConfig.kind == "ai", ConnectorConfig.enabled.is_(True))).first()
    if row:
        cfg.provider = row.provider
        cfg.model = row.settings.get("model") or cfg.model
        cfg.base_url = row.settings.get("base_url") or cfg.base_url
        cfg.external_processing_allowed = bool(row.settings.get("external_processing_acknowledged")) or cfg.external_processing_allowed
        cfg.pseudonymize = bool(row.settings.get("pseudonymize", cfg.pseudonymize))
        cfg.api_key = decrypt_secrets(row.secret_ciphertext).get("api_key")
    if provider_override:
        if provider_override not in ("deterministic", cfg.provider):
            raise ConnectorError("Fournisseur IA non configuré")
        cfg.provider = provider_override
    return cfg


async def run_analysis(db: Session, inv: Investigation, *, provider_override: str | None = None,
                       user_id: int | None = None, actor: str = "system") -> AIAnalysis:
    cfg = resolve_ai_config(db, provider_override)
    links = list(db.scalars(select(InvestigationIndicator).where(InvestigationIndicator.investigation_id == inv.id)))
    results = current_results(db, inv.id)
    record = AIAnalysis(investigation_id=inv.id, provider=cfg.provider, status="error", input_sha256="", created_by=user_id)
    if cfg.provider == "none":
        record.status, record.error_message = "disabled", "Analyse IA désactivée par la configuration."
        db.add(record)
        db.flush()
        return record
    provider = build_provider(cfg)
    external = getattr(provider, "external", True)
    package = build_evidence(inv, list(inv.events), links, results, pseudonymize=cfg.pseudonymize and external)
    record.input_sha256 = evidence_digest(package)
    record.injection_flags = injection_flags(package)
    record.model = provider.model
    if external and not cfg.external_processing_allowed:
        record.status = "disabled"
        record.error_message = ("Envoi à un fournisseur IA externe refusé : la politique de traitement des données n'a pas "
                                "été validée (external_processing_acknowledged / MAKKADI_AI_EXTERNAL_PROCESSING_ALLOWED).")
    else:
        try:
            raw: Any = await provider.analyze(package)
            record.data_sent_externally = external
            output, issues = validate_output(raw, package)
            record.validation_issues = issues
            if output is None:
                record.status = "rejected"
                record.error_message = "Réponse IA rejetée : non conforme au schéma."
            else:
                record.status = "ok"
                record.output = output.model_dump(mode="json")
        except ConnectorError as exc:
            record.status, record.error_message = "error", str(exc)
            record.data_sent_externally = external
    db.add(record)
    db.flush()
    audit.record(db, "ai.analysis", actor=actor, actor_user_id=user_id, target_type="investigation", target_id=inv.id,
                 details={"provider": cfg.provider, "model": record.model, "status": record.status,
                          "input_sha256": record.input_sha256, "external": record.data_sent_externally,
                          "injection_flags": len(record.injection_flags), "validation_issues": len(record.validation_issues)})
    return record
