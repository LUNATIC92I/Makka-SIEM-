"""Encryption of connector secrets (API keys, client secrets, tokens)."""

from __future__ import annotations

import json
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import get_settings
from app.security.keys import master_key

SECRET_MASK = "••••••••"


def _fernet() -> Fernet:
    return Fernet(master_key(get_settings()).encode())


def encrypt_secrets(values: dict[str, Any]) -> str | None:
    clean = {k: v for k, v in values.items() if v not in (None, "")}
    if not clean:
        return None
    return _fernet().encrypt(json.dumps(clean).encode()).decode()


def decrypt_secrets(token: str | None) -> dict[str, Any]:
    if not token:
        return {}
    try:
        return json.loads(_fernet().decrypt(token.encode()))
    except (InvalidToken, ValueError):
        # Master key changed or data corrupted: behave as "not configured".
        return {}


def masked(token: str | None) -> dict[str, str]:
    """Return the secret field names with masked values, for display."""
    return {k: SECRET_MASK for k in decrypt_secrets(token)}
