from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.providers import is_local_endpoint
from app.api.deps import DbDep, client_ip, require
from app.connectors.osint.base import ProviderContext
from app.connectors.osint.registry import CATALOG, REAL_PROVIDERS
from app.connectors.siem.connectors import SIEM_CONNECTORS
from app.core.errors import ConnectorError, OutboundBlocked
from app.core.timeutil import utc_now
from app.connectors.http import SafeHttpClient
from app.investigation.pipeline import build_siem_connector
from app.services.notifications import EMAIL_SECRETS, EMAIL_SETTINGS, LEVELS, validate_smtp_host, PROVIDERS as NOTIFY_PROVIDERS, SECRET_FIELDS as NOTIFY_SECRETS, SETTINGS_SCHEMA as NOTIFY_SCHEMA
from app.models import ConnectorConfig, User
from app.schemas.serializers import MATURITY_LABELS, connector_out
from app.security.secrets_vault import SECRET_MASK, decrypt_secrets, encrypt_secrets
from app.security.ssrf import validate_outbound_url
from app.services import audit

router = APIRouter(prefix="/connectors", tags=["connectors"])
AI_PROVIDERS = {"anthropic": "Anthropic Claude (API)", "openai_compatible": "Compatible OpenAI (local ou hébergé)",
                "deterministic": "Moteur déterministe local (sans LLM)"}
URL_KEYS = ("url", "base_url", "api_root")


@router.get("/catalog")
def catalog(_: User = Depends(require("connectors:read"))) -> dict:
    return {
        "siem": [{"provider": c.provider, "display_name": c.display_name, "description": c.description,
                  "settings_schema": c.settings_schema, "secret_fields": c.secret_fields + ["webhook_secret"],
                  "maturity": MATURITY_LABELS.get(c.maturity, c.maturity)} for c in SIEM_CONNECTORS.values()],
        "osint": [{"provider": c.name, "display_name": c.display_name, "category": c.category, "description": c.description,
                   "requires_api_key": c.requires_api_key, "secret_fields": c.secret_fields,
                   "settings_schema": c.settings_schema, "terms_url": c.terms_url,
                   "maturity": MATURITY_LABELS.get(c.maturity, c.maturity)} for c in REAL_PROVIDERS],
        "ai": [{"provider": k, "display_name": v} for k, v in AI_PROVIDERS.items()],
        "notification": [{"provider": k, "display_name": v,
                          "settings_schema": EMAIL_SETTINGS if k == "email" else NOTIFY_SCHEMA,
                          "secret_fields": EMAIL_SECRETS if k == "email" else NOTIFY_SECRETS}
                         for k, v in NOTIFY_PROVIDERS.items()],
    }


@router.get("")
def list_connectors(db: Session = DbDep, _: User = Depends(require("connectors:read"))) -> list[dict]:
    return [connector_out(c) for c in db.scalars(select(ConnectorConfig).order_by(ConnectorConfig.kind, ConnectorConfig.name))]


class ConnectorIn(BaseModel):
    kind: Literal["siem", "osint", "ai", "notification"]
    provider: str = Field(max_length=64)
    name: str = Field(pattern=r"^[a-zA-Z0-9_.-]{2,100}$")
    enabled: bool = False
    settings: dict[str, Any] = {}
    secrets: dict[str, str] = {}
    poll_interval_seconds: int = Field(default=300, ge=30, le=86400)


class ConnectorPatch(BaseModel):
    enabled: bool | None = None
    settings: dict[str, Any] | None = None
    secrets: dict[str, str] | None = None
    poll_interval_seconds: int | None = Field(default=None, ge=30, le=86400)


def _validate(kind: str, provider: str, settings: dict[str, Any]) -> None:
    valid = {"siem": SIEM_CONNECTORS, "osint": {p.name: p for p in REAL_PROVIDERS}, "ai": AI_PROVIDERS,
             "notification": NOTIFY_PROVIDERS}[kind]
    if provider not in valid:
        raise HTTPException(422, f"Fournisseur inconnu pour {kind} : {provider}")
    for key in URL_KEYS:
        if settings.get(key):
            url = str(settings[key])
            if kind == "ai" and is_local_endpoint(url):
                continue  # local model (Ollama, vLLM...) explicitly allowed for the AI provider
            try:
                validate_outbound_url(url)
            except OutboundBlocked as exc:
                raise HTTPException(422, f"URL refusée ({key}) : {exc}") from exc
    if len(str(settings)) > 50_000:
        raise HTTPException(422, "Paramètres trop volumineux")
    if kind == "notification" and settings.get("min_risk_level") not in (None, "", *LEVELS):
        raise HTTPException(422, "Seuil de risque invalide")
    if kind == "notification" and provider == "email" and settings.get("smtp_host"):
        try:
            validate_smtp_host(str(settings["smtp_host"]))
        except OutboundBlocked as exc:
            raise HTTPException(422, f"Serveur SMTP refusé : {exc}") from exc


def _validate_secret_url(kind: str, secrets: dict[str, str] | None) -> None:
    url = (secrets or {}).get("url")
    if kind == "notification" and url and url != SECRET_MASK:
        try:
            validate_outbound_url(url)
        except OutboundBlocked as exc:
            raise HTTPException(422, f"URL de webhook refusée : {exc}") from exc


def _merge_secrets(existing: str | None, incoming: dict[str, str] | None) -> str | None:
    if incoming is None:
        return existing
    current = decrypt_secrets(existing)
    for k, v in incoming.items():
        if v == SECRET_MASK:
            continue  # unchanged
        if v == "":
            current.pop(k, None)
        else:
            current[k] = v
    return encrypt_secrets(current)


@router.post("", status_code=201)
def create_connector(body: ConnectorIn, request: Request, db: Session = DbDep, user: User = Depends(require("connectors:write"))) -> dict:
    _validate(body.kind, body.provider, body.settings)
    _validate_secret_url(body.kind, body.secrets)
    if db.scalars(select(ConnectorConfig).where(ConnectorConfig.name == body.name)).first():
        raise HTTPException(409, "Nom déjà utilisé")
    if body.kind == "ai" and body.enabled:
        for other in db.scalars(select(ConnectorConfig).where(ConnectorConfig.kind == "ai")):
            other.enabled = False
    row = ConnectorConfig(kind=body.kind, provider=body.provider, name=body.name, enabled=body.enabled, settings=body.settings,
                          secret_ciphertext=_merge_secrets(None, body.secrets), poll_interval_seconds=body.poll_interval_seconds)
    db.add(row)
    db.flush()
    audit.record(db, "connector.created", actor=user.username, actor_user_id=user.id, target_type="connector", target_id=row.id,
                 details={"kind": body.kind, "provider": body.provider, "name": body.name, "enabled": body.enabled,
                          "secret_fields": sorted(body.secrets)}, client_ip=client_ip(request))
    db.commit()
    return connector_out(row)


@router.patch("/{connector_id}")
def update_connector(connector_id: int, body: ConnectorPatch, request: Request, db: Session = DbDep,
                     user: User = Depends(require("connectors:write"))) -> dict:
    row = db.get(ConnectorConfig, connector_id)
    if row is None:
        raise HTTPException(404, "Connecteur introuvable")
    changes: dict[str, Any] = {}
    if body.settings is not None:
        _validate(row.kind, row.provider, body.settings)
        row.settings = body.settings
        changes["settings"] = sorted(body.settings)
    if body.secrets is not None:
        _validate_secret_url(row.kind, body.secrets)
        row.secret_ciphertext = _merge_secrets(row.secret_ciphertext, body.secrets)
        changes["secrets_updated"] = sorted(k for k, v in body.secrets.items() if v != SECRET_MASK)
    if body.poll_interval_seconds is not None:
        row.poll_interval_seconds = changes["poll_interval_seconds"] = body.poll_interval_seconds
    if body.enabled is not None:
        if row.kind == "ai" and body.enabled:
            for other in db.scalars(select(ConnectorConfig).where(ConnectorConfig.kind == "ai", ConnectorConfig.id != row.id)):
                other.enabled = False
        row.enabled = changes["enabled"] = body.enabled
    row.updated_at = utc_now()
    audit.record(db, "connector.updated", actor=user.username, actor_user_id=user.id, target_type="connector", target_id=row.id,
                 details=changes, client_ip=client_ip(request))
    db.commit()
    return connector_out(row)


@router.delete("/{connector_id}", status_code=204)
def delete_connector(connector_id: int, request: Request, db: Session = DbDep, user: User = Depends(require("connectors:write"))) -> None:
    row = db.get(ConnectorConfig, connector_id)
    if row is None:
        raise HTTPException(404, "Connecteur introuvable")
    if row.kind == "osint" and row.provider in CATALOG:
        raise HTTPException(400, "Les sources OSINT du catalogue se désactivent, elles ne se suppriment pas")
    audit.record(db, "connector.deleted", actor=user.username, actor_user_id=user.id, target_type="connector",
                 target_id=row.id, details={"name": row.name}, client_ip=client_ip(request))
    db.delete(row)
    db.commit()


class TestIn(BaseModel):
    indicator_type: str = "ipv4"
    indicator_value: str = Field(default="", max_length=256)


@router.post("/{connector_id}/test")
async def test_connector(connector_id: int, body: TestIn, request: Request, db: Session = DbDep,
                         user: User = Depends(require("connectors:write"))) -> dict:
    """Real connectivity test. Only a successful test marks the connector as operational."""
    row = db.get(ConnectorConfig, connector_id)
    if row is None:
        raise HTTPException(404, "Connecteur introuvable")
    ok, message = False, ""
    try:
        if row.kind == "siem":
            message = await build_siem_connector(row).test_connection()
            ok = True
        elif row.kind == "osint":
            from app.services.indicators import validate_indicator

            ind = validate_indicator(body.indicator_type, body.indicator_value or "1.1.1.1")
            if ind.scope != "public":
                raise HTTPException(422, "Indicateur de test non public")
            provider = CATALOG[row.provider](ProviderContext(row.settings or {}, decrypt_secrets(row.secret_ciphertext)))
            result = await provider.lookup(ind.type, ind.value)
            ok = result.status in ("ok", "no_data")
            message = f"Statut : {result.status}" + (f", {result.error_message}" if result.error_message else "")
        elif row.kind == "notification" and row.provider == "email":
            import asyncio as _asyncio

            from app.services.notifications import _send_email

            await _asyncio.to_thread(_send_email, row.settings or {}, decrypt_secrets(row.secret_ciphertext),
                                     "MAKKADi : message de test", "Message de test (aucune donnée d'investigation).")
            ok, message = True, "E-mail de test envoyé"
        elif row.kind == "notification":
            secrets = decrypt_secrets(row.secret_ciphertext)
            if not secrets.get("url"):
                raise ConnectorError("URL du webhook non configurée")
            payload = {"text": "MAKKADi : message de test (aucune donnée d'investigation)."} if row.provider != "webhook" \
                else {"type": "test", "application": "MAKKADi"}
            resp = await SafeHttpClient().request("POST", secrets["url"], json=payload)
            ok = resp.status_code < 400
            message = f"Webhook : HTTP {resp.status_code}"
        else:
            message = "Le fournisseur IA est testé lors d'une analyse (aucune donnée envoyée ici)."
            ok = row.provider == "deterministic"
    except (ConnectorError, ValueError) as exc:
        message = str(exc)
    row.last_run_at = utc_now()
    row.last_status = "ok" if ok else "error"
    row.last_error = None if ok else message[:2000]
    if ok:
        row.last_success_at = utc_now()
    audit.record(db, "connector.tested", actor=user.username, actor_user_id=user.id, target_type="connector",
                 target_id=row.id, details={"ok": ok}, client_ip=client_ip(request))
    db.commit()
    return {"ok": ok, "message": message, "connector": connector_out(row)}
