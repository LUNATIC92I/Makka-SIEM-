"""Event ingestion: dedup, indicator extraction, investigation creation/grouping."""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.connectors.siem.base import NormalizedEvent, severity_at_least
from app.core.timeutil import utc_now
from app.models import Indicator, Investigation, InvestigationEvent, InvestigationIndicator, SiemEvent
from app.services import audit
from app.services.app_settings import get_setting
from app.services.indicators import ExtractedIndicator, extract_from_text, guess_type, validate_indicator
from app.services.tasks import enqueue

_ref_lock = threading.Lock()
OPEN_STATUSES = ("new", "in_progress", "pending_review")


@dataclass
class IngestStats:
    received: int = 0
    created: int = 0
    duplicates: int = 0
    investigations_created: int = 0
    investigations_updated: int = 0
    skipped_below_threshold: int = 0
    errors: list[str] = field(default_factory=list)
    event_ids: list[int] = field(default_factory=list)
    investigation_ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def extract_event_indicators(ev: SiemEvent) -> list[ExtractedIndicator]:
    found: dict[tuple[str, str], ExtractedIndicator] = {}
    for field_name, role in (("src_ip", "source"), ("dst_ip", "destination")):
        value = getattr(ev, field_name)
        if not value:
            continue
        t = guess_type(value)
        if t in ("ipv4", "ipv6", "domain"):
            try:
                ind = validate_indicator(t, value)
            except ValueError:
                continue
            ind.role, ind.extracted_from = role, field_name
            found[ind.key] = ind
    text = " ".join(filter(None, [ev.title, json.dumps(ev.context, default=str), json.dumps(ev.raw, default=str)[:100_000]]))
    for ind in extract_from_text(text, "raw"):
        if ind.key in found:
            continue
        ind.role = "observed"
        found[ind.key] = ind
    return list(found.values())


def _next_reference(db: Session) -> str:
    year = utc_now().year
    prefix = f"INV-{year}-"
    last = db.scalar(select(func.max(Investigation.reference)).where(Investigation.reference.like(f"{prefix}%")))
    number = int(last.rsplit("-", 1)[1]) + 1 if last else 1
    return f"{prefix}{number:06d}"


def _upsert_indicator(db: Session, ind: ExtractedIndicator) -> Indicator:
    row = db.scalars(select(Indicator).where(Indicator.type == ind.type, Indicator.value == ind.value)).first()
    now = utc_now()
    if row is None:
        row = Indicator(type=ind.type, value=ind.value, scope=ind.scope, classification=ind.classification,
                        first_seen=now, last_seen=now)
        db.add(row)
        db.flush()
    else:
        row.last_seen = now
    return row


def link_indicators(db: Session, inv: Investigation, ev: SiemEvent) -> int:
    added = 0
    for ind in extract_event_indicators(ev):
        row = _upsert_indicator(db, ind)
        exists = db.get(InvestigationIndicator, (inv.id, row.id, ind.role))
        if exists is None:
            db.add(InvestigationIndicator(investigation_id=inv.id, indicator_id=row.id, role=ind.role,
                                          extracted_from=ind.extracted_from, event_id=ev.id))
            added += 1
    db.flush()
    return added


def _find_open_investigation(db: Session, ev: SiemEvent, window_minutes: int) -> Investigation | None:
    if not ev.src_ip:
        return None
    since = utc_now() - timedelta(minutes=window_minutes)
    q = (
        select(Investigation)
        .join(InvestigationEvent, InvestigationEvent.investigation_id == Investigation.id)
        .join(SiemEvent, SiemEvent.id == InvestigationEvent.event_id)
        .where(SiemEvent.src_ip == ev.src_ip, Investigation.status.in_(OPEN_STATUSES),
               Investigation.updated_at >= since, Investigation.is_synthetic == ev.is_synthetic)
        .order_by(Investigation.updated_at.desc())
    )
    return db.scalars(q).first()


def ingest_events(
    db: Session, events: list[NormalizedEvent], *, method: str, connector_id: int | None = None,
    actor: str = "system", actor_user_id: int | None = None, auto_investigate: bool = True,
) -> IngestStats:
    stats = IngestStats(received=len(events))
    cfg = get_setting(db, "ingestion")
    touched: dict[str, Investigation] = {}
    for ne in events:
        dup = db.scalars(select(SiemEvent.id).where(SiemEvent.source_system == ne.source_system,
                                                    SiemEvent.original_id == ne.original_id)).first()
        if dup is not None:
            stats.duplicates += 1
            continue
        raw_json = json.dumps(ne.raw, sort_keys=True, default=str)
        ev = SiemEvent(
            connector_id=connector_id, source_system=ne.source_system, original_id=ne.original_id,
            content_hash=ne.content_hash(), ingest_method=method, event_time=ne.event_time, title=ne.title,
            event_type=ne.event_type, severity=ne.severity, severity_raw=ne.severity_raw, src_ip=ne.src_ip,
            dst_ip=ne.dst_ip, src_port=ne.src_port, dst_port=ne.dst_port, protocol=ne.protocol, hostname=ne.hostname,
            attempt_count=ne.attempt_count, context=ne.context, raw=ne.raw,
            raw_sha256=hashlib.sha256(raw_json.encode()).hexdigest(), is_synthetic=ne.is_synthetic,
        )
        db.add(ev)
        db.flush()
        stats.created += 1
        stats.event_ids.append(ev.id)
        if not auto_investigate:
            continue
        if not severity_at_least(ev.severity, cfg["auto_investigate_min_severity"]):
            stats.skipped_below_threshold += 1
            continue
        inv = _find_open_investigation(db, ev, int(cfg["group_window_minutes"])) if cfg.get("group_by_source_ip") else None
        if inv is None:
            inv = create_investigation(db, ev)
            stats.investigations_created += 1
        else:
            db.add(InvestigationEvent(investigation_id=inv.id, event_id=ev.id))
            inv.updated_at = utc_now()
            if _sev_rank(ev.severity) > _sev_rank(inv.severity):
                inv.severity = ev.severity
            stats.investigations_updated += 1
        link_indicators(db, inv, ev)
        touched[inv.id] = inv
    for inv in touched.values():
        enqueue(db, "run_investigation", {"investigation_id": inv.id}, dedup_key=f"investigate:{inv.id}")
        stats.investigation_ids.append(inv.id)
    audit.record(db, "ingest.events", actor=actor, actor_user_id=actor_user_id, target_type="connector",
                 target_id=connector_id, details={k: v for k, v in stats.as_dict().items() if k not in ("event_ids",)} | {"method": method})
    db.flush()
    return stats


def _sev_rank(sev: str) -> int:
    order = ["unknown", "info", "low", "medium", "high", "critical"]
    return order.index(sev) if sev in order else 0


def create_investigation(db: Session, ev: SiemEvent, owner_id: int | None = None) -> Investigation:
    with _ref_lock:
        reference = _next_reference(db)
        title = ev.title or f"Événement {ev.event_type}"
        if ev.src_ip:
            title = f"{title}, {ev.src_ip}"
        inv = Investigation(
            reference=reference, title=title[:500], severity=ev.severity, source_system=ev.source_system,
            is_synthetic=ev.is_synthetic, owner_id=owner_id,
            priority={"critical": "critical", "high": "high"}.get(ev.severity, "medium"),
        )
        db.add(inv)
        db.flush()
    db.add(InvestigationEvent(investigation_id=inv.id, event_id=ev.id))
    db.flush()
    audit.record(db, "investigation.created", target_type="investigation", target_id=inv.id,
                 details={"reference": inv.reference, "event": f"{ev.source_system}:{ev.original_id}"})
    return inv
