"""Hash-chained audit log.

Each entry stores ``prev_hash`` and ``entry_hash = sha256(prev_hash || canonical(entry))``.
``verify_chain`` detects modified, inserted or deleted rows. This is
tamper-*evident*: an attacker with write access to the DB could rebuild the
whole chain, so exporting the latest hash to an external system is recommended
for stronger guarantees (documented in docs/SECURITY.md).
"""

from __future__ import annotations

import hashlib
import json
import threading
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import iso, utc_now
from app.models import AuditLog

GENESIS = "0" * 64
_lock = threading.Lock()


def _digest(prev_hash: str, entry: AuditLog) -> str:
    canonical = json.dumps(
        {
            "ts": iso(entry.ts), "actor_user_id": entry.actor_user_id, "actor": entry.actor,
            "action": entry.action, "target_type": entry.target_type, "target_id": entry.target_id,
            "details": entry.details, "client_ip": entry.client_ip,
        },
        sort_keys=True, ensure_ascii=False, default=str,
    )
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def record(
    db: Session, action: str, *, actor: str = "system", actor_user_id: int | None = None,
    target_type: str | None = None, target_id: str | int | None = None,
    details: dict[str, Any] | None = None, client_ip: str | None = None,
) -> AuditLog:
    with _lock:
        last = db.scalars(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).first()
        prev = last.entry_hash if last else GENESIS
        entry = AuditLog(
            ts=utc_now(),
            actor_user_id=actor_user_id, actor=actor, action=action, target_type=target_type,
            target_id=None if target_id is None else str(target_id),
            details=json.loads(json.dumps(details or {}, default=str)), client_ip=client_ip, prev_hash=prev,
        )
        entry.entry_hash = _digest(prev, entry)
        db.add(entry)
        db.flush()
        return entry


def verify_chain(db: Session) -> dict[str, Any]:
    prev = GENESIS
    count = 0
    for entry in db.scalars(select(AuditLog).order_by(AuditLog.id)):
        count += 1
        if entry.prev_hash != prev or _digest(prev, entry) != entry.entry_hash:
            return {"valid": False, "entries_checked": count, "first_invalid_id": entry.id}
        prev = entry.entry_hash
    return {"valid": True, "entries_checked": count, "last_hash": prev}
