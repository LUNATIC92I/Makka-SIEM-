"""Persistent local key material (JWT signing secret, Fernet master key).

Keys are generated on first start and stored in the data directory, unless
provided via environment variables. On Windows they are encrypted with DPAPI
(bound to the Windows user account); elsewhere they are 0600 files. They are
never stored in the database.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

from app.core.config import Settings
from app.security import dpapi


def _read_or_create(path: Path, factory) -> str:  # noqa: ANN001
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = factory()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value)
    return value


def _read_or_create_protected(path: Path, factory) -> str:  # noqa: ANN001
    """On Windows, store the key encrypted with DPAPI (``<name>.dpapi``), migrating any clear-text file."""
    if not dpapi.available():
        return _read_or_create(path, factory)
    protected = path.with_name(path.name + ".dpapi")
    if protected.exists():
        return dpapi.unprotect(protected.read_bytes()).decode()
    value = path.read_text(encoding="utf-8").strip() if path.exists() else factory()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = protected.with_suffix(".tmp")
    tmp.write_bytes(dpapi.protect(value.encode()))
    tmp.replace(protected)
    if path.exists():
        path.unlink()  # clear-text copy removed once the protected copy exists
    return value


def jwt_secret(settings: Settings) -> str:
    if settings.jwt_secret:
        return settings.jwt_secret
    return _read_or_create_protected(settings.data_dir / "jwt.key", lambda: secrets.token_urlsafe(48))


def master_key(settings: Settings) -> str:
    if settings.master_key:
        return settings.master_key
    return _read_or_create_protected(settings.data_dir / "master.key", lambda: Fernet.generate_key().decode())
