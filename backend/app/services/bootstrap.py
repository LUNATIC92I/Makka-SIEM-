"""First-start initialisation: roles, OSINT source registry, connector placeholders."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.connectors.osint.registry import CATALOG, REAL_PROVIDERS
from app.models import ConnectorConfig, OsintSource, Role

PERMISSIONS = [
    "investigations:read", "investigations:write", "investigations:restricted", "reports:read", "reports:write",
    "ingest:write", "connectors:read", "connectors:write", "settings:read", "settings:write", "users:manage",
    "audit:read", "tasks:read", "tasks:write", "ai:run",
]
ROLES = {
    "admin": ("Administrateur : configuration, utilisateurs, accès à toutes les investigations", PERMISSIONS),
    "analyst": ("Analyste SOC : investigations, rapports, ingestion, analyse IA", [
        "investigations:read", "investigations:write", "reports:read", "reports:write", "ingest:write",
        "connectors:read", "settings:read", "tasks:read", "tasks:write", "ai:run", "audit:read"]),
    "viewer": ("Lecteur : consultation des investigations et rapports", ["investigations:read", "reports:read", "connectors:read"]),
}
# Keyless public sources: present but disabled until the operator enables them
# (enabling sends indicators to third parties).
KEYLESS = {"rdap", "ripestat", "greynoise", "internetdb", "crtsh", "dns", "ipinfo"}


def bootstrap(db: Session) -> None:
    for name, (desc, perms) in ROLES.items():
        role = db.scalars(select(Role).where(Role.name == name)).first()
        if role is None:
            db.add(Role(name=name, description=desc, permissions=perms))
        else:
            role.permissions, role.description = perms, desc
    for cls in CATALOG.values():
        src = db.get(OsintSource, cls.name) or OsintSource(name=cls.name)
        src.display_name, src.category, src.upstream_group = cls.display_name, cls.category, cls.upstream_group
        src.reliability, src.requires_api_key, src.terms_url = cls.reliability, cls.requires_api_key, cls.terms_url
        db.merge(src)
    existing = {r.name for r in db.scalars(select(ConnectorConfig).where(ConnectorConfig.kind == "osint"))}
    for cls in REAL_PROVIDERS:
        if cls.name not in existing:
            db.add(ConnectorConfig(kind="osint", provider=cls.name, name=cls.name, enabled=False, settings={}))
    db.commit()
