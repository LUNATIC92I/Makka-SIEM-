"""SIEM connector contract and event normalisation.

Each connector returns ``FetchResult`` objects: normalised events plus the next
cursor. The ingestion service persists events (deduplicated) *before*
committing the new cursor, so an interrupted collection resumes from the last
committed position without losing events (at-least-once + idempotent insert).
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from app.core.timeutil import iso, parse_timestamp
from app.security.sanitize import sanitize_structure

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_SEVERITY_ALIASES = {
    "informational": "info", "information": "info", "info": "info", "notice": "info", "debug": "info",
    "low": "low", "minor": "low", "warning": "low",
    "medium": "medium", "moderate": "medium", "med": "medium",
    "high": "high", "major": "high", "error": "high", "severe": "high",
    "critical": "critical", "crit": "critical", "emergency": "critical", "alert": "critical",
}


def normalize_severity(raw: Any, scale: str | None = None) -> str:
    """Map vendor severities onto info/low/medium/high/critical.

    Numeric scales: ``level15`` (Wazuh rule.level 0-15, default when <= 15),
    ``percent`` (0-100, e.g. Elastic risk_score; default when > 15), ``ten`` (0-10).
    """
    if raw is None or raw == "":
        return "unknown"
    numeric: float | None = None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        numeric = float(raw)
    elif isinstance(raw, str):
        try:
            numeric = float(raw.strip())
        except ValueError:
            numeric = None
    if numeric is None:
        return _SEVERITY_ALIASES.get(str(raw).strip().lower(), "unknown")
    scale = scale or ("percent" if numeric > 15 else "level15")
    if scale == "percent":
        bands = [(74, "critical"), (48, "high"), (22, "medium"), (1, "low")]
    elif scale == "ten":
        bands = [(9, "critical"), (7, "high"), (4, "medium"), (1, "low")]
    else:
        bands = [(12, "critical"), (8, "high"), (4, "medium"), (2, "low")]
    for threshold, label in bands:
        if numeric >= threshold:
            return label
    return "info"


def severity_at_least(severity: str, threshold: str) -> bool:
    if severity not in SEVERITY_ORDER:
        return True  # unknown severity: let the analyst decide
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)


class NormalizedEvent(BaseModel):
    source_system: str
    original_id: str = Field(min_length=1, max_length=255)
    event_time: datetime | None = None
    title: str = ""
    event_type: str = "unknown"
    severity: str = "unknown"
    severity_raw: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = None
    hostname: str | None = None
    attempt_count: int | None = Field(default=None, ge=0)
    context: dict[str, Any] = {}
    raw: dict[str, Any] = {}
    is_synthetic: bool = False

    def content_hash(self) -> str:
        basis = json.dumps(
            {
                "s": self.source_system, "t": iso(self.event_time), "title": self.title,
                "src": self.src_ip, "dst": self.dst_ip, "type": self.event_type, "host": self.hostname,
            },
            sort_keys=True,
        )
        return hashlib.sha256(basis.encode()).hexdigest()


def get_path(data: Any, path: str) -> Any:
    """Read a dotted path (``source.ip``, ``rule.level``, ``a.0.b``) from nested dicts/lists.

    Keys that themselves contain dots (flattened ECS) are tried first.
    """
    if not path:
        return None
    if isinstance(data, dict) and path in data:
        return data[path]
    cur: Any = data
    parts = path.split(".")
    i = 0
    while i < len(parts):
        if isinstance(cur, dict):
            # try the longest flattened key first
            for j in range(len(parts), i, -1):
                key = ".".join(parts[i:j])
                if key in cur:
                    cur = cur[key]
                    i = j
                    break
            else:
                return None
        elif isinstance(cur, list) and parts[i].isdigit() and int(parts[i]) < len(cur):
            cur = cur[int(parts[i])]
            i += 1
        else:
            return None
    return cur


def _first(raw: dict[str, Any], paths: list[str] | str | None) -> Any:
    if not paths:
        return None
    for p in [paths] if isinstance(paths, str) else paths:
        value = get_path(raw, p)
        if value not in (None, "", []):
            return value[0] if isinstance(value, list) and value and not isinstance(value[0], dict) else value
    return None


def _to_int(value: Any) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except (TypeError, ValueError):
        return None


DEFAULT_MAPPING: dict[str, list[str]] = {
    "original_id": ["id", "event_id", "eventId", "_id", "alert_id", "uuid"],
    "event_time": ["timestamp", "@timestamp", "time", "event_time", "_time", "created", "TimeGenerated"],
    "title": ["title", "name", "rule.name", "message", "description", "signature"],
    "event_type": ["event_type", "type", "category", "event.category", "rule.description"],
    "severity": ["severity", "level", "priority", "rule.level", "event.severity"],
    "src_ip": ["src_ip", "source_ip", "source.ip", "srcip", "src", "client_ip", "data.srcip"],
    "dst_ip": ["dst_ip", "destination_ip", "destination.ip", "dstip", "dest", "dest_ip"],
    "src_port": ["src_port", "source.port", "srcport", "spt"],
    "dst_port": ["dst_port", "destination.port", "dstport", "dest_port", "dpt"],
    "protocol": ["protocol", "network.transport", "proto", "transport"],
    "hostname": ["hostname", "host", "host.name", "dest_host", "agent.name", "computer", "target_host"],
    "attempt_count": ["attempt_count", "count", "attempts", "event.count", "previous_output_count"],
}


def normalize_with_mapping(
    raw: dict[str, Any], source_system: str, mapping: dict[str, list[str] | str] | None = None,
    *, is_synthetic: bool = False, context_fields: list[str] | None = None,
) -> NormalizedEvent:
    m: dict[str, Any] = {**DEFAULT_MAPPING, **(mapping or {})}
    original_id = _first(raw, m["original_id"])
    sev_raw = _first(raw, m["severity"])
    event_time = parse_timestamp(_first(raw, m["event_time"]))
    clean_raw = sanitize_structure(raw)
    if original_id in (None, ""):
        # No vendor id: derive a deterministic one from the raw content.
        original_id = "sha256:" + hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:40]
    host = _first(raw, m["hostname"])
    if isinstance(host, dict):
        host = host.get("name") or host.get("hostname")
    context = {f: get_path(raw, f) for f in (context_fields or []) if get_path(raw, f) is not None}
    return NormalizedEvent(
        source_system=source_system,
        original_id=str(original_id)[:255],
        event_time=event_time,
        title=str(_first(raw, m["title"]) or "")[:500],
        event_type=str(_first(raw, m["event_type"]) or "unknown")[:128],
        severity=normalize_severity(sev_raw, m.get("severity_scale")),
        severity_raw=None if sev_raw is None else str(sev_raw)[:64],
        src_ip=_str_or_none(_first(raw, m["src_ip"])),
        dst_ip=_str_or_none(_first(raw, m["dst_ip"])),
        src_port=_to_int(_first(raw, m["src_port"])),
        dst_port=_to_int(_first(raw, m["dst_port"])),
        protocol=_str_or_none(_first(raw, m["protocol"])),
        hostname=_str_or_none(host),
        attempt_count=_to_int(_first(raw, m["attempt_count"])),
        context=sanitize_structure(context),
        raw=clean_raw if isinstance(clean_raw, dict) else {"value": clean_raw},
        is_synthetic=is_synthetic or bool(raw.get("_makkadi_synthetic")),
    )


def _str_or_none(v: Any) -> str | None:
    if v is None or v == "":
        return None
    return str(v)[:255]


@dataclass
class FetchResult:
    events: list[NormalizedEvent]
    next_cursor: str | None
    has_more: bool = False
    warnings: list[str] = field(default_factory=list)


@dataclass
class ConnectorContext:
    name: str
    settings: dict[str, Any]
    secrets: dict[str, Any]


class SiemConnector(ABC):
    """Base class. Subclasses must be stateless across calls except for token caching."""

    provider: ClassVar[str]
    display_name: ClassVar[str]
    description: ClassVar[str]
    settings_schema: ClassVar[dict[str, str]] = {}
    secret_fields: ClassVar[list[str]] = []
    maturity: ClassVar[str] = "implemented-mock-tested"  # never "operational" without a live test

    def __init__(self, ctx: ConnectorContext):
        self.ctx = ctx

    @property
    def source_system(self) -> str:
        return self.ctx.settings.get("source_system") or self.provider

    def setting(self, key: str, default: Any = None) -> Any:
        value = self.ctx.settings.get(key, default)
        return default if value in (None, "") else value

    def require(self, key: str, *, secret: bool = False) -> Any:
        store = self.ctx.secrets if secret else self.ctx.settings
        value = store.get(key)
        if value in (None, ""):
            from app.core.errors import ConnectorError

            raise ConnectorError(f"Paramètre manquant: {key}")
        return value

    @abstractmethod
    async def fetch(self, cursor: str | None, limit: int = 200) -> FetchResult: ...

    async def test_connection(self) -> str:
        result = await self.fetch(None, limit=1)
        return f"Connexion réussie ({len(result.events)} événement(s) lu(s))"

    def normalize(self, raw: dict[str, Any]) -> NormalizedEvent:
        return normalize_with_mapping(
            raw, self.source_system, self.ctx.settings.get("field_mapping"),
            context_fields=self.ctx.settings.get("context_fields"),
        )
