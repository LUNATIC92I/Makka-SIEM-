"""Demo scenario loader (synthetic SIEM events, explicitly flagged)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.connectors.siem.connectors import parse_event_document
from app.core.timeutil import iso, parse_timestamp, utc_now
from app.services.ingestion import IngestStats, ingest_events


def sample_data_dir() -> Path:
    if getattr(sys, "_MEIPASS", None):
        return Path(sys._MEIPASS) / "sample_data"  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[3] / "sample_data"


def _rebase(doc: dict[str, Any]) -> dict[str, Any]:
    """Shift demo timestamps so the first event happens at its time-of-day on the latest past day."""
    events = doc["events"]
    first = parse_timestamp(events[0]["timestamp"])
    assert first is not None
    now = utc_now()
    target = now.replace(hour=first.hour, minute=first.minute, second=first.second, microsecond=0)
    if target > now:
        target -= timedelta(days=1)
    delta = target - first
    for ev in events:
        ts: datetime | None = parse_timestamp(ev.get("timestamp"))
        if ts:
            ev["timestamp"] = iso(ts + delta)
    return doc


def load_demo(db: Session, actor: str = "system", user_id: int | None = None) -> IngestStats:
    doc = json.loads((sample_data_dir() / "demo_scenario.json").read_text(encoding="utf-8"))
    doc = _rebase(doc)
    events = parse_event_document(doc, "demo-siem", is_synthetic=True)
    return ingest_events(db, events, method="demo", actor=actor, actor_user_id=user_id)
