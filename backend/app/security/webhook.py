"""HMAC-SHA256 signature verification for inbound SIEM webhooks.

Signature header: ``X-Makkadi-Signature: sha256=<hex>`` computed over
``f"{timestamp}.{raw_body}"`` with the connector's shared secret; the
``X-Makkadi-Timestamp`` header (epoch seconds) must be within the allowed skew,
which limits replay.
"""

from __future__ import annotations

import hashlib
import hmac
import time


def compute_signature(secret: str, timestamp: str, body: bytes) -> str:
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify_signature(secret: str, timestamp: str | None, signature: str | None, body: bytes, max_skew: int) -> bool:
    if not secret or not timestamp or not signature:
        return False
    try:
        ts = int(timestamp)
    except ValueError:
        return False
    if abs(time.time() - ts) > max_skew:
        return False
    return hmac.compare_digest(compute_signature(secret, timestamp, body), signature)
