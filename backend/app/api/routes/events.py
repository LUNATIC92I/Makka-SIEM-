from __future__ import annotations

import json

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DbDep, client_ip, require
from app.connectors.siem.connectors import parse_event_document
from app.core.config import get_settings
from app.core.errors import ConnectorError
from app.models import ConnectorConfig, SiemEvent, User
from app.schemas.serializers import event_out
from app.security.secrets_vault import decrypt_secrets
from app.security.webhook import verify_signature
from app.services import audit
from app.services.demo import load_demo
from app.services.ingestion import ingest_events

router = APIRouter(tags=["events"])
MAX_UPLOAD = 20 * 1024 * 1024


@router.get("/events")
def list_events(db: Session = DbDep, _: User = Depends(require("investigations:read")),
                page: int = 1, page_size: int = 50) -> dict:
    page_size = max(1, min(page_size, 200))
    total = db.scalar(select(func.count()).select_from(SiemEvent)) or 0
    rows = db.scalars(select(SiemEvent).order_by(SiemEvent.received_at.desc()).offset((max(page, 1) - 1) * page_size).limit(page_size))
    return {"total": total, "items": [event_out(e) for e in rows]}


@router.post("/ingest/file")
async def ingest_file(request: Request, file: UploadFile = File(...), db: Session = DbDep,
                      user: User = Depends(require("ingest:write"))) -> dict:
    data = await file.read(MAX_UPLOAD + 1)
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "Fichier trop volumineux (20 Mo max)")
    try:
        doc = json.loads(data)
        events = parse_event_document(doc, "json-import")
    except (ValueError, ConnectorError) as exc:
        raise HTTPException(422, f"Fichier JSON invalide : {exc}") from exc
    stats = ingest_events(db, events, method="file", actor=user.username, actor_user_id=user.id)
    audit.record(db, "ingest.file", actor=user.username, actor_user_id=user.id, client_ip=client_ip(request),
                 details={"file_name": (file.filename or "")[:200], "events": len(events)})
    db.commit()
    return stats.as_dict()


@router.post("/ingest/demo")
def ingest_demo(request: Request, db: Session = DbDep, user: User = Depends(require("ingest:write"))) -> dict:
    if not get_settings().demo_mode:
        raise HTTPException(403, "Mode démonstration désactivé")
    stats = load_demo(db, actor=user.username, user_id=user.id)
    db.commit()
    return stats.as_dict()


@router.post("/ingest/webhook/{connector_name}")
async def webhook(connector_name: str, request: Request, db: Session = DbDep) -> dict:
    """Inbound SIEM webhook authenticated by HMAC-SHA256 (no user session)."""
    row = db.scalars(select(ConnectorConfig).where(ConnectorConfig.name == connector_name,
                                                   ConnectorConfig.kind == "siem")).first()
    body = await request.body()
    if len(body) > MAX_UPLOAD:
        raise HTTPException(413, "Charge trop volumineuse")
    secret = decrypt_secrets(row.secret_ciphertext).get("webhook_secret") if row and row.enabled else None
    if not row or not row.enabled or not verify_signature(
        secret or "", request.headers.get("x-makkadi-timestamp"), request.headers.get("x-makkadi-signature"),
        body, get_settings().webhook_max_skew_seconds,
    ):
        audit.record(db, "ingest.webhook_rejected", actor="webhook", client_ip=client_ip(request),
                     details={"connector": connector_name[:100]})
        db.commit()
        raise HTTPException(401, "Signature invalide")
    try:
        events = parse_event_document(json.loads(body), row.settings.get("source_system") or row.provider,
                                      mapping=row.settings.get("field_mapping"))
    except (ValueError, ConnectorError) as exc:
        raise HTTPException(422, f"Charge invalide : {exc}") from exc
    stats = ingest_events(db, events, method="webhook", connector_id=row.id, actor=f"webhook:{row.name}")
    db.commit()
    return {k: v for k, v in stats.as_dict().items() if k in ("received", "created", "duplicates")}
