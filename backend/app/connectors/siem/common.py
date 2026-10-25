from __future__ import annotations

from datetime import timedelta

from app.core.timeutil import iso, parse_timestamp, utc_now


def initial_cursor(settings: dict, default_minutes: int = 60) -> str:
    minutes = int(settings.get("initial_lookback_minutes") or default_minutes)
    return iso(utc_now() - timedelta(minutes=minutes)) or ""


def max_timestamp(current: str | None, candidates: list) -> str | None:
    best = parse_timestamp(current) if current else None
    for c in candidates:
        ts = parse_timestamp(c)
        if ts and (best is None or ts > best):
            best = ts
    return iso(best) if best else current
