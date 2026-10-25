"""Data retention: purge of closed investigations, old raw events and finished tasks.

Audit logs are never purged automatically (their chain would break); export
them before any manual archival.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.timeutil import utc_now
from app.models import Investigation, InvestigationEvent, SiemEvent, Task
from app.services import audit
from app.services.app_settings import get_setting
from app.services.tasks import handler

CLOSED = ("closed_true_positive", "closed_false_positive", "closed_benign", "closed")


def purge(db: Session, actor: str = "system") -> dict[str, Any]:
    cfg = get_setting(db, "retention")
    now = utc_now()
    inv_cut = now - timedelta(days=int(cfg["investigations_days"]))
    ev_cut = now - timedelta(days=int(cfg["raw_events_days"]))
    task_cut = now - timedelta(days=int(cfg["tasks_days"]))
    old_invs = list(db.scalars(select(Investigation).where(Investigation.status.in_(CLOSED),
                                                           Investigation.updated_at < inv_cut)))
    for inv in old_invs:
        db.delete(inv)
    linked = select(InvestigationEvent.event_id)
    ev_res = db.execute(delete(SiemEvent).where(SiemEvent.received_at < ev_cut, SiemEvent.id.not_in(linked)))
    task_res = db.execute(delete(Task).where(Task.status.in_(("succeeded", "failed", "dead")), Task.created_at < task_cut))
    result = {"investigations": len(old_invs), "events": ev_res.rowcount or 0, "tasks": task_res.rowcount or 0}
    audit.record(db, "retention.purge", actor=actor, details=result)
    db.commit()
    return result


@handler("retention_purge")
async def _h_purge(db: Session, payload: dict[str, Any]) -> dict[str, Any]:
    return purge(db)
