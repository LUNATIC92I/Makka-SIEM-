"""Tasks, audit, settings, dashboard and system endpoints."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import DbDep, client_ip, require
from app.api.routes.investigations import visible_filter
from app.core.config import APP_VERSION, get_settings
from app.core.errors import ValidationFailed
from app.core.timeutil import iso, utc_now
from app.models import AuditLog, ConnectorConfig, Indicator, Investigation, InvestigationIndicator, SiemEvent, Task, User
from app.schemas.serializers import connector_out, investigation_summary, task_out
from app.services import audit
from app.services.active_checks import tcp_check
from app.services.app_settings import DEFAULTS, get_setting, put_setting
from app.services.retention import purge
from app.services.tasks import enqueue

router = APIRouter(tags=["operations"])


@router.get("/health")
def health() -> dict:
    s = get_settings()
    return {"status": "ok", "app_name": s.app_name, "version": APP_VERSION, "demo_mode": s.demo_mode, "time": iso(utc_now())}


@router.get("/meta")
def meta() -> dict:
    s = get_settings()
    return {"app_name": s.app_name, "tagline": s.app_tagline, "version": APP_VERSION, "demo_mode": s.demo_mode,
            "active_checks_enabled": s.active_checks_enabled}


# --------------------------------------------------------------------------- dashboard


@router.get("/dashboard")
def dashboard(db: Session = DbDep, user: User = Depends(require("investigations:read"))) -> dict:
    vis = visible_filter(user)
    invs = list(db.scalars(select(Investigation).where(vis).order_by(Investigation.created_at.desc()).limit(1000)))
    open_invs = [i for i in invs if not i.status.startswith("closed")]
    since = utc_now() - timedelta(days=14)
    per_day = Counter(i.created_at.date().isoformat() for i in invs if i.created_at >= since)
    priority = sorted(open_invs, key=lambda i: (-(i.risk_score or 0), -(i.confidence_score or 0)))[:8]
    recent_events = db.scalars(select(SiemEvent).order_by(SiemEvent.received_at.desc()).limit(8))
    in_progress = db.scalar(select(func.count()).select_from(Task).where(Task.status.in_(("pending", "running")))) or 0
    analyzing = db.scalar(select(func.count(func.distinct(InvestigationIndicator.indicator_id)))
                          .join(Investigation, Investigation.id == InvestigationIndicator.investigation_id)
                          .where(Investigation.pipeline_status.in_(("pending", "running")))) or 0
    activities = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(12)) if "audit:read" in user.role.permissions else []
    connectors = [connector_out(c) for c in db.scalars(select(ConnectorConfig).where(ConnectorConfig.enabled.is_(True)))]
    return {
        "counts": {
            "investigations": len(invs), "open": len(open_invs),
            "events": db.scalar(select(func.count()).select_from(SiemEvent)) or 0,
            "indicators": db.scalar(select(func.count()).select_from(Indicator)) or 0,
            "indicators_in_analysis": analyzing, "tasks_in_queue": in_progress,
        },
        "risk_distribution": dict(Counter(i.risk_level or "en attente" for i in open_invs)),
        "confidence_distribution": dict(Counter(i.confidence_level or "en attente" for i in open_invs)),
        "status_distribution": dict(Counter(i.status for i in invs)),
        "per_day": [{"date": (utc_now() - timedelta(days=d)).date().isoformat(),
                     "count": per_day.get((utc_now() - timedelta(days=d)).date().isoformat(), 0)} for d in range(13, -1, -1)],
        "priority_investigations": [investigation_summary(i) for i in priority],
        "recent_alerts": [{"id": e.id, "title": e.title, "severity": e.severity, "src_ip": e.src_ip, "hostname": e.hostname,
                           "event_time": iso(e.event_time), "source_system": e.source_system, "is_synthetic": e.is_synthetic}
                          for e in recent_events],
        "connectors": [{"name": c["name"], "kind": c["kind"], "state": c["state"], "last_error": c["last_error"],
                        "display_name": c.get("display_name", c["provider"])} for c in connectors],
        "activities": [{"ts": iso(a.ts), "actor": a.actor, "action": a.action, "target": f"{a.target_type or ''} {a.target_id or ''}".strip()}
                       for a in activities],
        "demo_mode": get_settings().demo_mode,
    }


# --------------------------------------------------------------------------- tasks


@router.get("/tasks")
def list_tasks(db: Session = DbDep, _: User = Depends(require("tasks:read")), status: str | None = None, limit: int = 100) -> dict:
    stmt = select(Task)
    if status:
        stmt = stmt.where(Task.status == status)
    rows = db.scalars(stmt.order_by(Task.id.desc()).limit(max(1, min(limit, 500))))
    counts = dict(db.execute(select(Task.status, func.count()).group_by(Task.status)).all())
    return {"counts": counts, "items": [task_out(t) for t in rows]}


@router.post("/tasks/{task_id}/retry")
def retry_task(task_id: int, request: Request, db: Session = DbDep, user: User = Depends(require("tasks:write"))) -> dict:
    task = db.get(Task, task_id)
    if task is None:
        raise HTTPException(404, "Tâche introuvable")
    if task.status not in ("failed", "dead"):
        raise HTTPException(409, "Seules les tâches en échec peuvent être relancées")
    task.status, task.attempts, task.next_run_at, task.finished_at = "pending", 0, utc_now(), None
    audit.record(db, "task.retried", actor=user.username, actor_user_id=user.id, target_type="task", target_id=task.id,
                 client_ip=client_ip(request))
    db.commit()
    return task_out(task)


@router.post("/connectors/{connector_id}/poll")
def poll_now(connector_id: int, db: Session = DbDep, user: User = Depends(require("ingest:write"))) -> dict:
    row = db.get(ConnectorConfig, connector_id)
    if row is None or row.kind != "siem":
        raise HTTPException(404, "Connecteur SIEM introuvable")
    task = enqueue(db, "poll_siem", {"connector_id": row.id}, dedup_key=f"poll:{row.id}", max_attempts=3)
    audit.record(db, "connector.poll_requested", actor=user.username, actor_user_id=user.id, target_type="connector", target_id=row.id)
    db.commit()
    return task_out(task)


# --------------------------------------------------------------------------- audit


@router.get("/audit")
def list_audit(db: Session = DbDep, _: User = Depends(require("audit:read")), target_id: str | None = None,
               action: str | None = None, limit: int = 200) -> list[dict]:
    stmt = select(AuditLog)
    if target_id:
        stmt = stmt.where(AuditLog.target_id == target_id)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    return [{"id": a.id, "ts": iso(a.ts), "actor": a.actor, "action": a.action, "target_type": a.target_type,
             "target_id": a.target_id, "details": a.details, "client_ip": a.client_ip, "entry_hash": a.entry_hash}
            for a in db.scalars(stmt.order_by(AuditLog.id.desc()).limit(max(1, min(limit, 1000))))]


@router.get("/audit/verify")
def verify_audit(db: Session = DbDep, _: User = Depends(require("audit:read"))) -> dict:
    return audit.verify_chain(db)


# --------------------------------------------------------------------------- settings


@router.get("/settings")
def read_settings(db: Session = DbDep, _: User = Depends(require("settings:read"))) -> dict:
    s = get_settings()
    return {
        **{k: get_setting(db, k) for k in DEFAULTS},
        "runtime": {  # read-only, from environment / .env
            "app_name": s.app_name, "host": s.host, "port": s.port, "demo_mode": s.demo_mode,
            "ai_provider_env": s.ai_provider, "ai_external_processing_allowed": s.ai_external_processing_allowed,
            "active_checks_enabled": s.active_checks_enabled, "active_checks_allowed_cidrs": s.active_checks_allowed_cidrs,
            "access_token_ttl_minutes": s.access_token_ttl_minutes, "rate_limit_per_minute": s.rate_limit_per_minute,
            "data_dir": str(s.data_dir), "database": "sqlite" if s.resolved_database_url.startswith("sqlite") else "postgresql",
        },
    }


class SettingsUpdate(BaseModel):
    value: dict[str, Any] = Field(...)


def _check_setting(key: str, value: dict[str, Any]) -> None:
    if key == "scoring":
        weights = value.get("risk_weights", {})
        if set(weights) - set(DEFAULTS["scoring"]["risk_weights"]) or any(not 0 <= float(w) <= 1 for w in weights.values()):
            raise HTTPException(422, "Pondérations invalides (clés connues, valeurs entre 0 et 1)")
    if key == "ingestion" and value.get("auto_investigate_min_severity") not in (None, "info", "low", "medium", "high", "critical"):
        raise HTTPException(422, "Seuil de sévérité invalide")
    if key == "assets":
        for level in (value.get("patterns") or {}).values():
            if level not in ("low", "medium", "high", "critical"):
                raise HTTPException(422, "Criticité invalide")
    if key == "retention":
        for k in ("investigations_days", "raw_events_days", "tasks_days"):
            if k in value and not 1 <= int(value[k]) <= 3650:
                raise HTTPException(422, "Durée de rétention invalide")


@router.put("/settings/{key}")
def update_settings(key: str, body: SettingsUpdate, request: Request, db: Session = DbDep,
                    user: User = Depends(require("settings:write"))) -> dict:
    if key not in DEFAULTS:
        raise HTTPException(404, "Paramètre inconnu")
    _check_setting(key, body.value)
    before = get_setting(db, key)
    after = put_setting(db, key, {**before, **body.value})
    audit.record(db, "settings.updated", actor=user.username, actor_user_id=user.id, target_type="settings", target_id=key,
                 details={"before": before, "after": after}, client_ip=client_ip(request))
    db.commit()
    return after


@router.post("/admin/retention/run")
def run_retention(db: Session = DbDep, user: User = Depends(require("settings:write"))) -> dict:
    return purge(db, actor=user.username)


class ActiveCheckIn(BaseModel):
    address: str = Field(max_length=64)
    ports: list[int] = Field(max_length=10)
    justification: str = Field(min_length=10, max_length=1000)


@router.post("/active-checks/tcp")
async def active_check(body: ActiveCheckIn, request: Request, db: Session = DbDep,
                       user: User = Depends(require("settings:write"))) -> dict:
    try:
        result = await tcp_check(body.address, body.ports)
    except ValidationFailed as exc:
        audit.record(db, "active_check.refused", actor=user.username, actor_user_id=user.id,
                     details={"address": body.address, "reason": str(exc)}, client_ip=client_ip(request))
        db.commit()
        raise HTTPException(403, str(exc)) from exc
    audit.record(db, "active_check.tcp", actor=user.username, actor_user_id=user.id, target_type="address",
                 target_id=body.address, details={"ports": body.ports, "justification": body.justification, "result": result},
                 client_ip=client_ip(request))
    db.commit()
    return {"address": body.address, "results": result}
