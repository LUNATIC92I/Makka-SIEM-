"""UTC time helpers. All timestamps stored by MAKKADi are timezone-aware UTC."""

from __future__ import annotations

from datetime import UTC, datetime


def utc_now() -> datetime:
    return datetime.now(UTC)


def ensure_utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC)


def parse_timestamp(value: object) -> datetime | None:
    """Parse ISO-8601 strings, epoch seconds/milliseconds, or datetimes into UTC."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return ensure_utc(value)
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value
        return datetime.fromtimestamp(seconds, UTC)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return parse_timestamp(int(text))
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        # Python's fromisoformat handles up to microseconds; trim nanoseconds.
        if "." in text:
            head, _, tail = text.partition(".")
            frac = "".join(ch for ch in tail if ch.isdigit())
            rest = tail[len(frac):]
            text = f"{head}.{frac[:6]}{rest}"
        try:
            return ensure_utc(datetime.fromisoformat(text))
        except ValueError:
            return None
    return None


def iso(dt: datetime | None) -> str | None:
    dt = ensure_utc(dt)
    return dt.isoformat().replace("+00:00", "Z") if dt else None
