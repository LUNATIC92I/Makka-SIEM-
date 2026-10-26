"""Outbound notifications when an investigation reaches a risk threshold.

Channels: generic JSON webhook (optionally HMAC-signed), Microsoft Teams and Slack
incoming webhooks. The webhook URL is stored encrypted (it is a secret for Teams/Slack)
and every request goes through the SSRF guard. Payloads are minimal: no raw event,
no OSINT payload. A notification is sent once per investigation and per level, and
again only if the risk level escalates.
"""

from __future__ import annotations

import asyncio
import json
import smtplib
import ssl
import time
from email.message import EmailMessage
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.http import SafeHttpClient
from app.core.config import get_settings
from app.core.errors import ConnectorError
from app.core.timeutil import iso, utc_now
from app.models import ConnectorConfig, Investigation
from app.security.secrets_vault import decrypt_secrets
from app.security.ssrf import validate_outbound_url
from app.security.webhook import compute_signature
from app.services import audit
from app.services.tasks import enqueue, handler

PROVIDERS = {"webhook": "Webhook JSON générique", "teams": "Microsoft Teams (webhook entrant)",
             "slack": "Slack (webhook entrant)", "email": "E-mail (SMTP avec TLS)"}
LEVELS = ["faible", "modéré", "élevé", "critique"]
SETTINGS_SCHEMA = {"min_risk_level": "Seuil : faible | modéré | élevé | critique (défaut élevé)",
                   "include_synthetic": "true pour notifier aussi les données de démonstration"}
SECRET_FIELDS = ["url", "webhook_secret"]
EMAIL_SETTINGS = {"smtp_host": "Serveur SMTP", "smtp_port": "587 (STARTTLS) ou 465 (TLS)", "mail_from": "Expéditeur",
                  "mail_to": "Destinataires (séparés par des virgules)", **SETTINGS_SCHEMA}
EMAIL_SECRETS = ["username", "password"]


def _rank(level: str | None) -> int:
    return LEVELS.index(level) if level in LEVELS else -1


def _truthy(value: Any) -> bool:
    return value is True or str(value).strip().lower() in ("1", "true", "oui", "yes")


def maybe_notify(db: Session, inv: Investigation) -> int:
    """Queue notifications for an investigation whose risk crossed a channel threshold."""
    level = inv.risk_level
    if _rank(level) < 0 or _rank(level) <= _rank(inv.notified_risk_level):
        return 0
    queued = 0
    channels = db.scalars(select(ConnectorConfig).where(ConnectorConfig.kind == "notification", ConnectorConfig.enabled.is_(True)))
    for ch in channels:
        threshold = (ch.settings or {}).get("min_risk_level") or "élevé"
        if _rank(level) < _rank(threshold):
            continue
        if inv.is_synthetic and not _truthy((ch.settings or {}).get("include_synthetic")):
            continue
        enqueue(db, "notify", {"investigation_id": inv.id, "connector_id": ch.id, "level": level},
                dedup_key=f"notify:{inv.id}:{ch.id}:{level}", max_attempts=4)
        queued += 1
    if queued:
        inv.notified_risk_level = level
    return queued


def build_payload(provider: str, inv: Investigation) -> dict[str, Any]:
    app_name = get_settings().app_name
    first = inv.events[0] if inv.events else None
    facts = {
        "reference": inv.reference, "title": inv.title, "risk_level": inv.risk_level, "risk_score": inv.risk_score,
        "confidence_level": inv.confidence_level, "confidence_score": inv.confidence_score, "severity": inv.severity,
        "source_ip": first.src_ip if first else None, "event_count": len(inv.events),
        "synthetic_data": inv.is_synthetic, "created_at": iso(inv.created_at),
    }
    demo = " [DONNÉES DE DÉMONSTRATION]" if inv.is_synthetic else ""
    text = (f"**{app_name}**, investigation {inv.reference}{demo}\n"
            f"Risque **{inv.risk_level}** ({inv.risk_score}/100), confiance {inv.confidence_level} "
            f"({inv.confidence_score}/100)\n{inv.title}\nÀ examiner par un analyste : aucune action n'a été déclenchée.")
    if provider in ("teams", "slack"):
        return {"text": text}
    return {"application": app_name, "type": "investigation.risk_threshold", "sent_at": iso(utc_now()), **facts}


def validate_smtp_host(host: str) -> None:
    """Same destination policy as HTTP connectors (anti-SSRF)."""
    validate_outbound_url(f"https://{host}/")


def _send_email(settings: dict[str, Any], secrets: dict[str, Any], subject: str, text: str) -> None:
    host = str(settings.get("smtp_host") or "")
    recipients = [a.strip() for a in str(settings.get("mail_to") or "").split(",") if a.strip()]
    if not host or not recipients or not settings.get("mail_from"):
        raise ConnectorError("Paramètres SMTP incomplets (smtp_host, mail_from, mail_to)")
    validate_smtp_host(host)
    port = int(settings.get("smtp_port") or 587)
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, str(settings["mail_from"]), ", ".join(recipients)
    msg.set_content(text)
    context = ssl.create_default_context()
    timeout = get_settings().http_timeout_seconds
    try:
        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=timeout)
            server.starttls(context=context)  # TLS is mandatory: no clear-text fallback
        with server:
            if secrets.get("username"):
                server.login(str(secrets["username"]), str(secrets.get("password", "")))
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as exc:
        raise ConnectorError(f"Échec d'envoi SMTP ({type(exc).__name__})", retryable=True) from exc


async def send(db: Session, channel: ConnectorConfig, inv: Investigation) -> None:
    secrets = decrypt_secrets(channel.secret_ciphertext)
    if channel.provider == "email":
        text = build_payload("slack", inv)["text"].replace("**", "")
        subject = f"[{get_settings().app_name}] {inv.reference}, risque {inv.risk_level}"
        await asyncio.to_thread(_send_email, channel.settings or {}, secrets, subject, text)
        return
    url = secrets.get("url")
    if not url:
        raise ConnectorError("URL du webhook non configurée")
    body = json.dumps(build_payload(channel.provider, inv), ensure_ascii=False).encode()
    headers = {"Content-Type": "application/json"}
    if channel.provider == "webhook" and secrets.get("webhook_secret"):
        ts = str(int(time.time()))
        headers |= {"X-Makkadi-Timestamp": ts, "X-Makkadi-Signature": compute_signature(secrets["webhook_secret"], ts, body)}
    resp = await SafeHttpClient().request("POST", url, content=body, headers=headers)
    if resp.status_code >= 400:
        raise ConnectorError(f"Le webhook a refusé la notification (HTTP {resp.status_code})",
                             retryable=resp.status_code >= 500, status_code=resp.status_code)


@handler("notify")
async def _h_notify(db: Session, payload: dict[str, Any]) -> dict[str, Any]:
    inv = db.get(Investigation, payload["investigation_id"])
    channel = db.get(ConnectorConfig, int(payload["connector_id"]))
    if inv is None or channel is None or not channel.enabled:
        return {"skipped": True}
    try:
        await send(db, channel, inv)
    except ConnectorError as exc:
        channel.last_status, channel.last_error, channel.last_run_at = "error", str(exc), utc_now()
        db.commit()
        raise
    channel.last_status, channel.last_error = "ok", None
    channel.last_run_at = channel.last_success_at = utc_now()
    audit.record(db, "notification.sent", target_type="investigation", target_id=inv.id,
                 details={"channel": channel.name, "provider": channel.provider, "level": payload.get("level")})
    db.commit()
    return {"sent": True, "channel": channel.name}
