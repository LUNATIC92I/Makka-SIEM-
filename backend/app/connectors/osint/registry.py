"""OSINT provider catalogue and instantiation from stored connector configuration."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.osint.abuseipdb import AbuseIpDbProvider
from app.connectors.osint.base import OsintProvider, ProviderContext
from app.connectors.osint.crtsh import CrtShProvider
from app.connectors.osint.demo import DEMO_PROVIDERS
from app.connectors.osint.dns_resolver import DnsProvider
from app.connectors.osint.greynoise import GreyNoiseProvider
from app.connectors.osint.internal_list import InternalListProvider
from app.connectors.osint.internetdb import InternetDbProvider
from app.connectors.osint.ipinfo import IpInfoProvider
from app.connectors.osint.maxmind import MaxMindProvider
from app.connectors.osint.misp import MispProvider
from app.connectors.osint.otx import OtxProvider
from app.connectors.osint.rdap import RdapProvider
from app.connectors.osint.ripestat import RipeStatProvider
from app.connectors.osint.taxii import TaxiiProvider
from app.connectors.osint.urlhaus import UrlhausProvider
from app.connectors.osint.virustotal import VirusTotalProvider
from app.core.config import get_settings
from app.models import ConnectorConfig
from app.security.secrets_vault import decrypt_secrets

REAL_PROVIDERS: list[type[OsintProvider]] = [
    RdapProvider, RipeStatProvider, IpInfoProvider, MaxMindProvider, VirusTotalProvider, AbuseIpDbProvider,
    OtxProvider, UrlhausProvider, GreyNoiseProvider, InternetDbProvider, CrtShProvider, DnsProvider,
    MispProvider, TaxiiProvider, InternalListProvider,
]
CATALOG: dict[str, type[OsintProvider]] = {p.name: p for p in REAL_PROVIDERS + DEMO_PROVIDERS}


def active_providers(db: Session) -> list[OsintProvider]:
    """Providers enabled by the operator, plus synthetic sources when demo mode is on."""
    providers: list[OsintProvider] = []
    rows = db.scalars(select(ConnectorConfig).where(ConnectorConfig.kind == "osint", ConnectorConfig.enabled.is_(True)))
    for row in rows:
        cls = CATALOG.get(row.provider)
        if cls is None or cls.is_synthetic_provider:
            continue
        providers.append(cls(ProviderContext(settings=row.settings or {}, secrets=decrypt_secrets(row.secret_ciphertext))))
    if get_settings().demo_mode:
        providers.extend(cls(ProviderContext(settings={}, secrets={})) for cls in DEMO_PROVIDERS)
    return providers
