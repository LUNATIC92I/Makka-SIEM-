"""OSINT provider contract and normalised findings.

Rules enforced here:
* a provider never fabricates data: when it cannot answer, it returns a result
  with ``status`` != ``ok`` and the UI shows "Donnée indisponible";
* every result records the source, the queried indicator, the query time, the
  data's own update time when known, a raw payload (or digest) and a reference URL;
* synthetic (demo) results are flagged ``is_synthetic``.
"""

from __future__ import annotations

import hashlib
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, Field

from app.core.errors import ConnectorError, OutboundBlocked, RateLimited
from app.core.timeutil import utc_now
from app.security.sanitize import sanitize_structure

ResultStatus = Literal["ok", "no_data", "error", "not_configured", "rate_limited", "skipped", "unsupported"]
UNAVAILABLE = "Donnée indisponible"


class NetworkInfo(BaseModel):
    registered_org: str | None = None  # organisation holding the IP block (RIR registration)
    network_name: str | None = None
    cidr: str | None = None
    rir: str | None = None
    registration_country: str | None = None
    asn: int | None = None
    as_name: str | None = None  # network operator announcing the prefix
    isp: str | None = None  # access provider when stated by the source
    bgp_prefix: str | None = None
    registered_at: datetime | None = None
    updated_at: datetime | None = None


class GeoInfo(BaseModel):
    country: str | None = None
    country_code: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = Field(default=None, ge=-90, le=90)
    longitude: float | None = Field(default=None, ge=-180, le=180)
    accuracy_radius_km: float | None = None
    precision_note: str | None = None


class Reputation(BaseModel):
    verdict: Literal["malicious", "suspicious", "benign", "unknown"] = "unknown"
    score: float | None = Field(default=None, ge=0, le=100)  # normalised 0-100 maliciousness
    raw_score: str | None = None
    detections: int | None = None
    total_engines: int | None = None
    report_count: int | None = None
    categories: list[str] = []
    last_reported_at: datetime | None = None
    explanation: str | None = None


class Resolution(BaseModel):
    type: str  # A, AAAA, PTR, CNAME, MX, NS
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    temporality: Literal["current", "historical", "unknown"] = "unknown"


class Certificate(BaseModel):
    sha256: str | None = None
    subject_cn: str | None = None
    issuer: str | None = None
    sans: list[str] = []
    not_before: datetime | None = None
    not_after: datetime | None = None
    reference_url: str | None = None


class RelatedIndicator(BaseModel):
    type: str
    value: str
    relation: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None


class Campaign(BaseModel):
    name: str
    reference: str | None = None
    source_statement: str | None = None


class ExposedServices(BaseModel):
    ports: list[int] = []
    hostnames: list[str] = []
    tags: list[str] = []
    vulns: list[str] = []
    cpes: list[str] = []


class Findings(BaseModel):
    network: NetworkInfo | None = None
    geo: GeoInfo | None = None
    reputation: Reputation | None = None
    resolutions: list[Resolution] = []
    certificates: list[Certificate] = []
    related: list[RelatedIndicator] = []
    campaigns: list[Campaign] = []
    services: ExposedServices | None = None
    tags: list[str] = []
    notes: list[str] = []


@dataclass
class ProviderResult:
    source_name: str
    indicator_type: str
    indicator_value: str
    status: ResultStatus
    queried_at: datetime = field(default_factory=utc_now)
    findings: Findings = field(default_factory=Findings)
    raw: Any = None
    reference_url: str | None = None
    data_updated_at: datetime | None = None
    source_confidence: str | None = None
    error_message: str | None = None
    access_notes: str | None = None
    duration_ms: int | None = None
    is_synthetic: bool = False

    @property
    def raw_sha256(self) -> str | None:
        if self.raw is None:
            return None
        return hashlib.sha256(json.dumps(self.raw, sort_keys=True, default=str).encode()).hexdigest()


@dataclass
class ProviderContext:
    settings: dict[str, Any]
    secrets: dict[str, Any]
    enabled: bool = True


class OsintProvider(ABC):
    name: ClassVar[str]
    display_name: ClassVar[str]
    category: ClassVar[str]  # network|geolocation|reputation|infrastructure|services|threat_intel
    supported_types: ClassVar[set[str]]
    requires_api_key: ClassVar[bool] = False
    upstream_group: ClassVar[str]  # sources sharing an upstream feed share a group
    reliability: ClassVar[float] = 0.6  # 0..1, documented in docs/SCORING.md
    terms_url: ClassVar[str | None] = None
    description: ClassVar[str] = ""
    settings_schema: ClassVar[dict[str, str]] = {}
    secret_fields: ClassVar[list[str]] = []
    is_synthetic_provider: ClassVar[bool] = False
    maturity: ClassVar[str] = "implemented-mock-tested"

    def __init__(self, ctx: ProviderContext):
        self.ctx = ctx

    def is_configured(self) -> bool:
        if not self.requires_api_key:
            return True
        return all(self.ctx.secrets.get(f) for f in (self.secret_fields or ["api_key"]))

    def _result(self, ind_type: str, value: str, status: ResultStatus, **kw: Any) -> ProviderResult:
        return ProviderResult(self.name, ind_type, value, status, is_synthetic=self.is_synthetic_provider, **kw)

    async def lookup(self, ind_type: str, value: str) -> ProviderResult:
        """Public entry point: never raises, always returns a traceable result."""
        if ind_type not in self.supported_types:
            return self._result(ind_type, value, "unsupported", error_message="Type d'indicateur hors périmètre de la source")
        if not self.is_configured():
            return self._result(ind_type, value, "not_configured", error_message="Clé API non configurée")
        start = time.monotonic()
        try:
            result = await self._lookup(ind_type, value)
        except RateLimited as exc:
            result = self._result(ind_type, value, "rate_limited", error_message=str(exc))
        except OutboundBlocked as exc:
            result = self._result(ind_type, value, "error", error_message=f"Destination refusée: {exc}")
        except ConnectorError as exc:
            result = self._result(ind_type, value, "error", error_message=str(exc))
        except Exception as exc:  # noqa: BLE001 - provider bugs must not break the pipeline
            result = self._result(ind_type, value, "error", error_message=f"Erreur interne du connecteur ({type(exc).__name__})")
        result.duration_ms = int((time.monotonic() - start) * 1000)
        if result.raw is not None:
            result.raw = sanitize_structure(result.raw, max_str=4000)
        return result

    @abstractmethod
    async def _lookup(self, ind_type: str, value: str) -> ProviderResult: ...
