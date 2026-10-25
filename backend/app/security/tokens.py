from __future__ import annotations

from datetime import timedelta

import jwt

from app.core.config import get_settings
from app.core.timeutil import utc_now
from app.security.keys import jwt_secret

ALGORITHM = "HS256"


def create_access_token(user_id: int, token_version: int) -> tuple[str, int]:
    settings = get_settings()
    ttl = settings.access_token_ttl_minutes * 60
    now = utc_now()
    payload = {
        "sub": str(user_id),
        "ver": token_version,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl)).timestamp()),
        "iss": "makkadi",
    }
    return jwt.encode(payload, jwt_secret(settings), algorithm=ALGORITHM), ttl


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token, jwt_secret(get_settings()), algorithms=[ALGORITHM], issuer="makkadi",
        options={"require": ["exp", "sub", "iat"]},
    )
