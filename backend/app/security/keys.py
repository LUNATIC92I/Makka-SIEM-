"""Persistent local key material (JWT signing secret, Fernet master key).

Keys are generated on first start and stored in the data directory with
restrictive permissions, unless provided via environment variables. They are
never stored in the database.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from cryptography.fernet import Fernet

from app.core.config import Settings


def _read_or_create(path: Path, factory) -> str:  # noqa: ANN001
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    value = factory()
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value)
    return value


def jwt_secret(settings: Settings) -> str:
    if settings.jwt_secret:
        return settings.jwt_secret
    return _read_or_create(settings.data_dir / "jwt.key", lambda: secrets.token_urlsafe(48))


def master_key(settings: Settings) -> str:
    if settings.master_key:
        return settings.master_key
    return _read_or_create(settings.data_dir / "master.key", lambda: Fernet.generate_key().decode())
